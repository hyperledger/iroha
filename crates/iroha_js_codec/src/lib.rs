//! Canonical account and instruction codecs shared by JavaScript platform adapters.
//!
//! This crate owns strict JSON admission and native Norito reconstruction. Platform
//! adapters only convert buffers and errors; they do not duplicate ledger codecs.

mod activation_instructions;
mod error;
mod game_instructions;
mod json_u64;
mod kaigi;
mod lifecycle_instructions;
mod manifest;
mod plain_governance;
mod retail_daily_limit_instructions;
mod staking_instructions;
mod verifying_key_instructions;
pub use error::{CodecError, CodecErrorKind, CodecResult};
mod archive;
pub use archive::{decode_instruction_archive, encode_instruction_archive};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use iroha_crypto::Hash;
use iroha_data_model::account::Account;
use iroha_data_model::account::AccountId;
use iroha_data_model::account::NewAccount;
use iroha_data_model::account::address::AccountAddress;
use iroha_data_model::account::address::AccountAddressError;
use iroha_data_model::account::address::{ChainDiscriminantGuard, chain_discriminant};
use iroha_data_model::asset::AssetDefinitionAlias;
use iroha_data_model::asset::AssetTransferAvailability;
use iroha_data_model::asset::AssetTransferControlWindow;
use iroha_data_model::asset::AssetTransferLimit;
use iroha_data_model::asset::definition::AssetDefinition;
use iroha_data_model::asset::definition::NewAssetDefinition;
use iroha_data_model::asset::id::AssetDefinitionId;
use iroha_data_model::asset::id::AssetId;
use iroha_data_model::asset::validate_asset_transfer_availability_reason;
use iroha_data_model::domain::Domain;
use iroha_data_model::domain::NewDomain;
use iroha_data_model::escrow::EscrowId;
use iroha_data_model::governance::types::AbiVersion;
use iroha_data_model::governance::types::ContractAbiHash;
use iroha_data_model::governance::types::ContractCodeHash;
use iroha_data_model::isi::Burn;
use iroha_data_model::isi::BurnBox;
use iroha_data_model::isi::CreateKaigi;
use iroha_data_model::isi::CustomInstruction;
use iroha_data_model::isi::EndKaigi;
use iroha_data_model::isi::ExecuteTrigger;
use iroha_data_model::isi::Grant;
use iroha_data_model::isi::GrantBox;
use iroha_data_model::isi::Instruction as InstructionTrait;
use iroha_data_model::isi::InstructionBox;
use iroha_data_model::isi::JoinKaigi;
use iroha_data_model::isi::LeaveKaigi;
use iroha_data_model::isi::Mint;
use iroha_data_model::isi::MintBox;
use iroha_data_model::isi::RecordKaigiUsage;
use iroha_data_model::isi::Register;
use iroha_data_model::isi::RegisterBox;
use iroha_data_model::isi::RegisterDataspaceAssetDefinition;
use iroha_data_model::isi::RegisterKaigiRelay;
use iroha_data_model::isi::RegisterPeerWithPop;
use iroha_data_model::isi::RemoveKeyValue;
use iroha_data_model::isi::ReportKaigiRelayHealth;
use iroha_data_model::isi::SetAssetDefinitionAlias;
use iroha_data_model::isi::SetKaigiRelayManifest;
use iroha_data_model::isi::SetKeyValue;
use iroha_data_model::isi::SetKeyValueBox;
use iroha_data_model::isi::SetParameter;
use iroha_data_model::isi::Transfer;
use iroha_data_model::isi::TransferAssetBatch;
use iroha_data_model::isi::TransferBox;
use iroha_data_model::isi::Unregister;
use iroha_data_model::isi::UnregisterBox;
use iroha_data_model::isi::UnregisterKaigiRelay;
use iroha_data_model::isi::asset_transfer_control::SetAssetTransferAvailability;
use iroha_data_model::isi::asset_transfer_control::SetAssetTransferBlacklist;
use iroha_data_model::isi::asset_transfer_control::SetAssetTransferControl;
use iroha_data_model::isi::escrow::CancelAssetLock;
use iroha_data_model::isi::governance::CastZkBallot;
use iroha_data_model::isi::governance::ProposeDeployContract;
use iroha_data_model::isi::governance::ProposeValidationFeePolicy;
use iroha_data_model::isi::governance::RegisterCitizen;
use iroha_data_model::isi::ministry::SubmitAgendaProposal;
use iroha_data_model::isi::rwa::ForceTransferRwa;
use iroha_data_model::isi::rwa::FreezeRwa;
use iroha_data_model::isi::rwa::HoldRwa;
use iroha_data_model::isi::rwa::MergeRwas;
use iroha_data_model::isi::rwa::RedeemRwa;
use iroha_data_model::isi::rwa::RegisterRwa;
use iroha_data_model::isi::rwa::ReleaseRwa;
use iroha_data_model::isi::rwa::RwaInstructionBox;
use iroha_data_model::isi::rwa::SetRwaControls;
use iroha_data_model::isi::rwa::TransferRwa;
use iroha_data_model::isi::rwa::UnfreezeRwa;
use iroha_data_model::isi::settlement::DvpIsi;
use iroha_data_model::isi::settlement::FundFxCorridorEscrow;
use iroha_data_model::isi::settlement::PvpIsi;
use iroha_data_model::isi::settlement::RefundFxCorridorEscrow;
use iroha_data_model::isi::settlement::SetFxCorridorPolicy;
use iroha_data_model::isi::settlement::SettleFxCorridor;
use iroha_data_model::isi::settlement::SettlementInstructionBox;
use iroha_data_model::isi::smart_contract_code::CancelSmartContractCodeUpload;
use iroha_data_model::isi::smart_contract_code::RegisterSmartContractBytes;
use iroha_data_model::isi::smart_contract_code::RegisterSmartContractCode;
use iroha_data_model::isi::smart_contract_code::RemoveSmartContractBytes;
use iroha_data_model::isi::social::CancelTwitterEscrow;
use iroha_data_model::isi::social::ClaimTwitterFollowReward;
use iroha_data_model::isi::social::SendToTwitter;
use iroha_data_model::isi::zk::CancelConfidentialPolicyTransition;
use iroha_data_model::isi::zk::CreateElection;
use iroha_data_model::isi::zk::FinalizeElection;
use iroha_data_model::isi::zk::RegisterZkAsset;
use iroha_data_model::isi::zk::ScheduleConfidentialPolicyTransition;
use iroha_data_model::isi::zk::SubmitBallot;
use iroha_data_model::kaigi::KaigiId;
use iroha_data_model::kaigi::KaigiParticipantCommitment;
use iroha_data_model::kaigi::KaigiParticipantNullifier;
use iroha_data_model::kaigi::KaigiRelayHealthStatus;
use iroha_data_model::kaigi::KaigiRelayRegistration;
use iroha_data_model::kaigi::scalar::KaigiAuthorizationScalarV1;
use iroha_data_model::ministry::AgendaProposalV1;
use iroha_data_model::nft::NewNft;
use iroha_data_model::nft::Nft;
use iroha_data_model::nft::NftId;
use iroha_data_model::oracle::KeyedHash;
use iroha_data_model::parameter::CustomParameter;
use iroha_data_model::parameter::Parameter;
use iroha_data_model::peer::Peer;
use iroha_data_model::permission::Permission;
use iroha_data_model::role::NewRole;
use iroha_data_model::role::Role;
use iroha_data_model::role::RoleId;
use iroha_data_model::rwa::NewRwa;
use iroha_data_model::rwa::RwaControlPolicy;
use iroha_data_model::rwa::RwaId;
use iroha_data_model::rwa::RwaParentRef;
use iroha_data_model::smart_contract::manifest::ContractManifest;
use iroha_data_model::trigger::Trigger;
use iroha_data_model::trigger::TriggerId;
use iroha_data_model::trigger::action::Action;
use iroha_data_model::validation_fee::ValidationFeePolicyV1;
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name::Name;
use iroha_model_base::peer::PeerId;
use iroha_primitives::json::Json;
use iroha_primitives::numeric::Quantity;
use norito::core as norito_core;
use norito::json;
use std::fmt;
use std::panic::AssertUnwindSafe;
use std::panic::catch_unwind;
use std::str::FromStr;

macro_rules! norito_json {
    ({ $($key:literal : $value:expr),+ $(,)? }) => {{
        let mut object = norito::json::Map::new();
        $(object.insert($key.to_string(), norito::json::to_value(&$value)
            .expect("serialize shared canonical instruction JSON"));)*
        norito::json::Value::Object(object)
    }};
}

/// Native admission result for an exact encoded account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedAccountAddress {
    /// Canonical account controller envelope, without a chain prefix.
    pub canonical_bytes: Vec<u8>,
    /// Chain discriminant decoded from the admitted I105 literal.
    pub network_prefix: u16,
}

/// Native rendering of an admitted account controller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenderedAccountAddress {
    /// Exact lowercase canonical hexadecimal controller envelope.
    pub canonical_hex: String,
    /// Exact I105 literal for the requested chain discriminant.
    pub i105: String,
}

/// Parse exact I105 with native controller admission and an optional network constraint.
///
/// # Errors
///
/// Returns a [`CodecErrorKind::InvalidArgument`] error carrying the canonical account
/// error code when `input` is not exact I105 for the expected network or its controller
/// cannot be rendered, and a [`CodecErrorKind::Failure`] if the canonical hexadecimal
/// cannot be decoded.
pub fn account_address_parse_encoded(
    input: &str,
    expected_prefix: Option<u16>,
) -> CodecResult<ParsedAccountAddress> {
    let address =
        AccountAddress::parse_encoded(input, expected_prefix).map_err(account_address_err)?;
    let network_prefix = match expected_prefix {
        Some(prefix) => prefix,
        None => AccountAddress::i105_discriminant(input).map_err(account_address_err)?,
    };
    let canonical_hex = address.canonical_hex().map_err(account_address_err)?;
    let hex_body = canonical_hex
        .strip_prefix("0x")
        .unwrap_or(canonical_hex.as_str());
    let canonical = hex::decode(hex_body).map_err(|err| CodecError::failure(err.to_string()))?;
    Ok(ParsedAccountAddress {
        canonical_bytes: canonical,
        network_prefix,
    })
}

/// Admit exact canonical controller bytes and render them for the requested network.
///
/// # Errors
///
/// Returns a [`CodecErrorKind::InvalidArgument`] error carrying the canonical account
/// error code when `bytes` is not an admitted controller envelope or cannot be rendered
/// for `network_prefix`.
pub fn account_address_render(
    bytes: &[u8],
    network_prefix: u16,
) -> CodecResult<RenderedAccountAddress> {
    let address = AccountAddress::from_canonical_bytes(bytes).map_err(account_address_err)?;
    let canonical_hex = address.canonical_hex().map_err(account_address_err)?;
    let i105 = address
        .to_i105_for_discriminant(network_prefix)
        .map_err(account_address_err)?;
    Ok(RenderedAccountAddress {
        canonical_hex,
        i105,
    })
}

/// Admit a JavaScript numeric network prefix without truncation or integer wrapping.
///
/// # Errors
///
/// Returns a [`CodecErrorKind::InvalidArgument`] error unless `prefix` is a finite
/// integer between 0 and 65535.
pub fn checked_network_prefix(prefix: f64) -> CodecResult<u16> {
    if !prefix.is_finite() || prefix.fract() != 0.0 || !(0.0..=65535.0).contains(&prefix) {
        return Err(CodecError::new(
            CodecErrorKind::InvalidArgument,
            "network prefix must be an integer between 0 and 65535",
        ));
    }
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "prefix was checked above to be a finite integer within 0..=65535"
    )]
    let prefix = prefix as u16;
    Ok(prefix)
}

/// Parse an instruction account operand under the caller's selected network scope.
///
/// Typed native callers must enter `ChainDiscriminantGuard` before calling this helper.
///
/// # Errors
///
/// Returns a [`CodecErrorKind::InvalidArgument`] error naming `label` when `input` is
/// not an account literal admitted under the selected network scope.
pub fn parse_account_id(input: &str, label: &str) -> CodecResult<AccountId> {
    let parsed = match AccountAddress::parse_encoded(input, Some(chain_discriminant())) {
        Ok(address) => address.to_account_id().map_err(|err| err.to_string()),
        Err(AccountAddressError::UnsupportedAddressFormat) => {
            AccountId::parse_encoded(input).map_err(|err| err.to_string())
        }
        Err(err) => Err(err.to_string()),
    };
    parsed.map_err(|err| {
        CodecError::new(
            CodecErrorKind::InvalidArgument,
            format!("invalid {label}: {err}"),
        )
    })
}

/// Encode the strict JavaScript instruction JSON contract into a public Norito frame.
///
/// `network_prefix` selects account admission and rendering for this operation only.
///
/// # Errors
///
/// Returns an error when the JSON is malformed, violates a strict instruction contract
/// or names an account outside `network_prefix`, or when Norito encoding fails.
pub fn encode_instruction_frame(json_payload: &str, network_prefix: u16) -> CodecResult<Vec<u8>> {
    let _network = ChainDiscriminantGuard::enter(network_prefix);
    let instruction = instruction_from_json(json_payload)?;
    let encoded = norito::encode_canonical(&instruction).map_err(codec_error)?;
    Ok(encoded)
}

/// Decode an exact public instruction frame into the strict JavaScript JSON contract.
///
/// Domainless account identities are rendered with the required `network_prefix`.
///
/// # Errors
///
/// Returns an error when the bytes are not an exact public `InstructionBox` frame
/// (including decoder panics), or when the instruction has no strict JSON rendering.
pub fn decode_instruction_frame(bytes: &[u8], network_prefix: u16) -> CodecResult<String> {
    let _network = ChainDiscriminantGuard::enter(network_prefix);
    let decode = catch_unwind(AssertUnwindSafe(|| {
        let slice = bytes;
        let instruction = decode_instruction_aligned(slice).map_err(codec_error)?;
        let value = instruction_to_json_value(&instruction)?;
        json::to_json(&value).map_err(codec_error)
    }));
    match decode {
        Ok(result) => result,
        Err(payload) => {
            let message = payload
                .downcast_ref::<&str>()
                .copied()
                .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
                .unwrap_or("unknown panic");
            Err(CodecError::new(
                CodecErrorKind::Failure,
                format!("panic during Norito decode: {message}"),
            ))
        }
    }
}

/// Decode exactly the current public `InstructionBox` frame.
///
/// Concrete instruction frames belong inside the registered box. They are not
/// alternative public frames and are never retried after box admission fails.
///
/// # Errors
///
/// Returns the Norito error when `bytes` is not exactly one canonical `InstructionBox`
/// frame.
pub fn decode_instruction_aligned(bytes: &[u8]) -> Result<InstructionBox, norito_core::Error> {
    norito::decode_canonical::<InstructionBox>(bytes)
}

/// Preserve the canonical account error code and diagnostic for platform adapters.
pub fn account_address_err(err: AccountAddressError) -> CodecError {
    CodecError::new(
        CodecErrorKind::InvalidArgument,
        format!("{}: {err}", err.code_str()),
    )
}

fn codec_error<E: fmt::Display>(error: E) -> CodecError {
    CodecError::new(CodecErrorKind::Failure, error.to_string())
}

fn parse_hash_string(input: &str, context: &str) -> CodecResult<Hash> {
    let trimmed = input.trim();
    if trimmed.starts_with("hash:") {
        return json::from_value(json::Value::String(trimmed.to_owned())).map_err(codec_error);
    }
    if trimmed.len() != Hash::LENGTH * 2
        || !trimmed
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c.is_ascii_whitespace())
    {
        return Err(CodecError::new(
            CodecErrorKind::InvalidArgument,
            format!("{context} must be a 64-character hexadecimal hash literal"),
        ));
    }
    let uppercase = trimmed.to_ascii_uppercase();
    Hash::from_str(&uppercase).map_err(|err| {
        CodecError::new(
            CodecErrorKind::InvalidArgument,
            format!("{context} invalid hash literal: {err}"),
        )
    })
}

/// Parse the hash representation accepted by existing instruction operands.
///
/// # Errors
///
/// Returns an error when the value is neither an accepted hash literal nor a hash JSON
/// value.
pub fn parse_hash_value(value: json::Value, context: &str) -> CodecResult<Hash> {
    match value {
        json::Value::String(ref s) => parse_hash_string(s, context),
        other => json::from_value(other).map_err(codec_error),
    }
}

fn parse_canonical_hash_value(value: json::Value, context: &str) -> CodecResult<Hash> {
    json::from_value(value).map_err(|err| {
        CodecError::new(
            CodecErrorKind::InvalidArgument,
            format!("{context} must be a canonical uppercase checksummed hash literal: {err}"),
        )
    })
}

fn parse_optional_hash(value: Option<json::Value>, context: &str) -> CodecResult<Option<Hash>> {
    match value {
        None | Some(json::Value::Null) => Ok(None),
        Some(value) => parse_hash_value(value, context).map(Some),
    }
}

fn parse_optional_string_value(
    value: Option<json::Value>,
    context: &str,
) -> CodecResult<Option<String>> {
    match value {
        None | Some(json::Value::Null) => Ok(None),
        Some(json::Value::String(s)) => Ok(Some(s)),
        Some(other) => parse_string_value(other, context).map(Some),
    }
}

fn parse_keyed_hash(value: json::Value, context: &str) -> CodecResult<KeyedHash> {
    let mut map = match value {
        json::Value::Object(map) => map,
        other => {
            return Err(CodecError::new(
                CodecErrorKind::InvalidArgument,
                format!("{context} must be an object (found {other:?})"),
            ));
        }
    };
    let pepper_id = parse_string_value(
        required_value(&mut map, "pepper_id", context)?,
        &format!("{context}.pepper_id"),
    )?;
    let digest = parse_hash_value(
        required_value(&mut map, "digest", context)?,
        &format!("{context}.digest"),
    )?;
    Ok(KeyedHash { pepper_id, digest })
}

/// Parse an optional Kaigi authorization scalar with native validation.
///
/// # Errors
///
/// Returns a [`CodecErrorKind::InvalidArgument`] error when a present, non-null value
/// is not a valid Kaigi authorization scalar.
pub fn parse_optional_kaigi_scalar(
    value: Option<json::Value>,
    context: &str,
) -> CodecResult<Option<KaigiAuthorizationScalarV1>> {
    match value {
        None | Some(json::Value::Null) => Ok(None),
        Some(value) => json::from_value(value).map(Some).map_err(|err| {
            CodecError::new(CodecErrorKind::InvalidArgument, format!("{context}: {err}"))
        }),
    }
}

/// Parse an optional Kaigi participant commitment with native validation.
///
/// # Errors
///
/// Returns a [`CodecErrorKind::InvalidArgument`] error when a present, non-null value
/// is not a valid Kaigi participant commitment.
pub fn parse_optional_commitment(
    value: Option<json::Value>,
    context: &str,
) -> CodecResult<Option<KaigiParticipantCommitment>> {
    match value {
        None | Some(json::Value::Null) => Ok(None),
        Some(value) => json::from_value(value).map(Some).map_err(|err| {
            CodecError::new(
                CodecErrorKind::InvalidArgument,
                format!("{context}.commitment: {err}"),
            )
        }),
    }
}

/// Parse an optional Kaigi participant nullifier with native validation.
///
/// # Errors
///
/// Returns a [`CodecErrorKind::InvalidArgument`] error when a present, non-null value
/// is not a valid Kaigi participant nullifier.
pub fn parse_optional_nullifier(
    value: Option<json::Value>,
    context: &str,
) -> CodecResult<Option<KaigiParticipantNullifier>> {
    match value {
        None | Some(json::Value::Null) => Ok(None),
        Some(value) => json::from_value(value).map(Some).map_err(|err| {
            CodecError::new(
                CodecErrorKind::InvalidArgument,
                format!("{context}.nullifier: {err}"),
            )
        }),
    }
}

/// Render an optional Kaigi authorization scalar as its canonical JSON value.
pub fn optional_kaigi_scalar_to_json(value: Option<&KaigiAuthorizationScalarV1>) -> json::Value {
    value.map_or(json::Value::Null, |scalar| {
        json::to_value(scalar).expect("Kaigi scalar serialization")
    })
}

fn optional_hash_to_json(value: Option<&Hash>) -> json::Value {
    value.map_or(json::Value::Null, |hash| {
        json::to_value(hash).expect("hash serialization")
    })
}

/// Render an optional participant commitment as its canonical JSON value.
pub fn optional_commitment_to_json(value: Option<&KaigiParticipantCommitment>) -> json::Value {
    value.map_or(json::Value::Null, |commitment| {
        json::to_value(commitment).expect("Kaigi commitment serialization")
    })
}

/// Render an optional participant nullifier as its canonical JSON value.
pub fn optional_nullifier_to_json(value: Option<&KaigiParticipantNullifier>) -> json::Value {
    value.map_or(json::Value::Null, |nullifier| {
        json::to_value(nullifier).expect("Kaigi nullifier serialization")
    })
}

fn optional_proof_to_json(value: Option<&Vec<u8>>) -> json::Value {
    value.map_or(json::Value::Null, |bytes| {
        json::Value::String(STANDARD.encode(bytes))
    })
}

fn parse_optional_base64(
    value: Option<json::Value>,
    context: &str,
) -> CodecResult<Option<Vec<u8>>> {
    match value {
        None | Some(json::Value::Null) => Ok(None),
        Some(json::Value::String(s)) => STANDARD.decode(s.as_bytes()).map(Some).map_err(|err| {
            CodecError::new(
                CodecErrorKind::InvalidArgument,
                format!("{context} must be a valid base64 string: {err}"),
            )
        }),
        Some(other) => json::from_value(other).map_err(codec_error),
    }
}

fn parse_base64(value: json::Value, context: &str) -> CodecResult<Vec<u8>> {
    match value {
        json::Value::String(s) => STANDARD.decode(s.as_bytes()).map_err(|err| {
            CodecError::new(
                CodecErrorKind::InvalidArgument,
                format!("{context} must be a valid base64 string: {err}"),
            )
        }),
        json::Value::Array(bytes) => {
            let mut buffer = Vec::with_capacity(bytes.len());
            for (index, value) in bytes.into_iter().enumerate() {
                let number = match value {
                    json::Value::Number(n) => n.as_u64().ok_or_else(|| {
                        CodecError::new(
                            CodecErrorKind::InvalidArgument,
                            format!("{context}[{index}] must be an unsigned byte"),
                        )
                    })?,
                    other => {
                        return Err(CodecError::new(
                            CodecErrorKind::InvalidArgument,
                            format!("{context}[{index}] must be an unsigned byte, found {other:?}"),
                        ));
                    }
                };
                if number > 0xFF {
                    return Err(CodecError::new(
                        CodecErrorKind::InvalidArgument,
                        format!("{context}[{index}] must be between 0 and 255"),
                    ));
                }
                buffer.push(u8::try_from(number).expect("validated byte range"));
            }
            Ok(buffer)
        }
        other => Err(CodecError::new(
            CodecErrorKind::InvalidArgument,
            format!("{context} must be a base64 string or byte array (found {other:?})"),
        )),
    }
}

fn required_value(map: &mut json::Map, key: &str, context: &str) -> CodecResult<json::Value> {
    map.remove(key).ok_or_else(|| {
        CodecError::new(
            CodecErrorKind::InvalidArgument,
            format!("{context}.{key} field missing"),
        )
    })
}

fn parse_string_value(value: json::Value, context: &str) -> CodecResult<String> {
    match value {
        json::Value::String(s) => Ok(s),
        other => Err(CodecError::new(
            CodecErrorKind::InvalidArgument,
            format!("{context} must be a string (found {other:?})"),
        )),
    }
}

fn parse_account_id_value(value: json::Value, context: &str) -> CodecResult<AccountId> {
    let literal = parse_string_value(value, context)?;
    parse_account_id(&literal, context)
}

fn parse_rwa_id_value(value: json::Value, context: &str) -> CodecResult<RwaId> {
    let literal = parse_string_value(value, context)?;
    literal.parse().map_err(|err| {
        CodecError::new(
            CodecErrorKind::InvalidArgument,
            format!("invalid RWA id `{literal}`: {err}"),
        )
    })
}

/// Render an instruction account operand as its canonical I105 literal.
///
/// # Errors
///
/// Returns a [`CodecErrorKind::InvalidArgument`] error when the account cannot be
/// rendered as canonical I105.
pub fn account_id_to_canonical_i105(account_id: &AccountId) -> CodecResult<String> {
    account_id.canonical_i105().map_err(|err| {
        CodecError::new(
            CodecErrorKind::InvalidArgument,
            format!("failed to encode account id as canonical I105: {err}"),
        )
    })
}

/// Parse and validate the complete list of RWA parent references.
///
/// # Errors
///
/// Returns an error when the value is not an array of objects with a valid `rwa` id
/// and `quantity`.
pub fn parse_rwa_parent_refs_value(
    value: json::Value,
    context: &str,
) -> CodecResult<Vec<RwaParentRef>> {
    let json::Value::Array(entries) = value else {
        return Err(CodecError::new(
            CodecErrorKind::InvalidArgument,
            format!("{context} must be an array"),
        ));
    };
    let mut parents = Vec::with_capacity(entries.len());
    for (index, entry) in entries.into_iter().enumerate() {
        let entry_context = format!("{context}[{index}]");
        let json::Value::Object(mut fields) = entry else {
            return Err(CodecError::new(
                CodecErrorKind::InvalidArgument,
                format!("{entry_context} must be an object"),
            ));
        };
        let rwa = parse_rwa_id_value(
            required_value(&mut fields, "rwa", &entry_context)?,
            &format!("{entry_context}.rwa"),
        )?;
        let quantity: Quantity =
            json::from_value(required_value(&mut fields, "quantity", &entry_context)?)
                .map_err(codec_error)?;
        parents.push(RwaParentRef::new(rwa, quantity));
    }
    Ok(parents)
}

/// Render RWA parent references without changing their JSON contract.
pub fn rwa_parent_refs_to_json(parents: &[RwaParentRef]) -> json::Value {
    json::Value::Array(
        parents
            .iter()
            .map(|parent| {
                norito_json!({
                    "rwa": parent.rwa().to_string(),
                    "quantity": parent.quantity(),
                })
            })
            .collect(),
    )
}

fn rwa_status_to_json(status: Option<&Name>) -> json::Value {
    status.map_or(json::Value::Null, |status| {
        json::Value::String(status.to_string())
    })
}

fn rwa_control_policy_to_json(policy: &RwaControlPolicy) -> CodecResult<json::Value> {
    let controller_accounts = policy
        .controller_accounts()
        .iter()
        .map(account_id_to_canonical_i105)
        .collect::<CodecResult<Vec<_>>>()?;
    let mut payload = json::Map::new();
    payload.insert(
        "controller_accounts".to_owned(),
        json::to_value(&controller_accounts).map_err(codec_error)?,
    );
    payload.insert(
        "controller_roles".to_owned(),
        json::to_value(
            &policy
                .controller_roles()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
        )
        .map_err(codec_error)?,
    );
    payload.insert(
        "freeze_enabled".to_owned(),
        json::Value::Bool(*policy.freeze_enabled()),
    );
    payload.insert(
        "hold_enabled".to_owned(),
        json::Value::Bool(*policy.hold_enabled()),
    );
    payload.insert(
        "force_transfer_enabled".to_owned(),
        json::Value::Bool(*policy.force_transfer_enabled()),
    );
    payload.insert(
        "redeem_enabled".to_owned(),
        json::Value::Bool(*policy.redeem_enabled()),
    );
    Ok(json::Value::Object(payload))
}

/// Render a new RWA, including its typed control policy and parent references.
///
/// # Errors
///
/// Returns an error when a controller account cannot be rendered as canonical I105 or
/// the control policy cannot be serialized.
pub fn new_rwa_to_json(rwa: &NewRwa) -> CodecResult<json::Value> {
    Ok(norito_json!({
        "domain": rwa.domain(),
        "quantity": rwa.quantity(),
        "spec": rwa.spec(),
        "primary_reference": rwa.primary_reference(),
        "status": rwa_status_to_json(rwa.status().as_ref()),
        "metadata": rwa.metadata(),
        "parents": rwa_parent_refs_to_json(rwa.parents()),
        "controls": rwa_control_policy_to_json(rwa.controls())?,
    }))
}

fn normalize_zk_ballot_public_inputs_json(raw: &str, context: &str) -> CodecResult<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(CodecError::new(
            CodecErrorKind::InvalidArgument,
            format!("{context} must be valid JSON"),
        ));
    }
    let mut value: json::Value = json::from_str(trimmed).map_err(|err| {
        CodecError::new(
            CodecErrorKind::InvalidArgument,
            format!("{context} must be valid JSON: {err}"),
        )
    })?;
    normalize_zk_ballot_public_inputs(&mut value, context)?;
    json::to_string(&value).map_err(|err| {
        CodecError::new(
            CodecErrorKind::InvalidArgument,
            format!("{context} must be valid JSON: {err}"),
        )
    })
}

/// Validate and normalize the account, amount, and hash inputs of a ZK ballot.
///
/// # Errors
///
/// Returns a [`CodecErrorKind::InvalidArgument`] error when the value is not an object,
/// uses an unsupported key alias, carries malformed 32-byte hex, supplies an incomplete
/// lock-hint set, or uses a noncanonical owner or amount.
pub fn normalize_zk_ballot_public_inputs(
    value: &mut json::Value,
    context: &str,
) -> CodecResult<()> {
    let map = match value {
        json::Value::Object(map) => map,
        other => {
            return Err(CodecError::new(
                CodecErrorKind::InvalidArgument,
                format!("{context} must be a JSON object (found {other:?})"),
            ));
        }
    };
    reject_zk_public_input_key(map, "durationBlocks", "duration_blocks", context)?;
    reject_zk_public_input_key(map, "root_hint_hex", "root_hint", context)?;
    reject_zk_public_input_key(map, "rootHintHex", "root_hint", context)?;
    reject_zk_public_input_key(map, "rootHint", "root_hint", context)?;
    reject_zk_public_input_key(map, "nullifier_hex", "nullifier", context)?;
    reject_zk_public_input_key(map, "nullifierHex", "nullifier", context)?;
    canonicalize_hex32_public_input(map, "root_hint", "root_hint", context)?;
    canonicalize_hex32_public_input(map, "nullifier", "nullifier", context)?;
    let has_owner = zk_hint_present(map, "owner");
    let has_amount = zk_hint_present(map, "amount");
    let has_duration = zk_hint_present(map, "duration_blocks");
    let any = has_owner || has_amount || has_duration;
    if any && !(has_owner && has_amount && has_duration) {
        return Err(CodecError::new(
            CodecErrorKind::InvalidArgument,
            format!(
                "{context} must include owner, amount, and duration_blocks when providing lock hints"
            ),
        ));
    }
    ensure_zk_public_input_owner_canonical(map, context)?;
    ensure_zk_public_input_amount_canonical(map, context)?;
    Ok(())
}

fn reject_zk_public_input_key(
    map: &json::Map,
    key: &str,
    canonical: &str,
    context: &str,
) -> CodecResult<()> {
    if map.contains_key(key) {
        return Err(CodecError::new(
            CodecErrorKind::InvalidArgument,
            format!("{context} must use {canonical} (unsupported key {key})"),
        ));
    }
    Ok(())
}

fn ensure_zk_public_input_owner_canonical(map: &json::Map, context: &str) -> CodecResult<()> {
    let Some(value) = map.get("owner") else {
        return Ok(());
    };
    if matches!(value, json::Value::Null) {
        return Ok(());
    }
    let owner = value.as_str().ok_or_else(|| {
        CodecError::new(
            CodecErrorKind::InvalidArgument,
            format!("{context}.owner must be a canonical I105 account id"),
        )
    })?;
    let canonical = AccountId::parse_encoded(owner)
        .map(|account| account.to_string())
        .map_err(|_| {
            CodecError::new(
                CodecErrorKind::InvalidArgument,
                format!("{context}.owner must be a canonical I105 account id"),
            )
        })?;
    if canonical != owner {
        return Err(CodecError::new(
            CodecErrorKind::InvalidArgument,
            format!("{context}.owner must use canonical I105 account id form"),
        ));
    }
    Ok(())
}

fn ensure_zk_public_input_amount_canonical(map: &json::Map, context: &str) -> CodecResult<()> {
    let Some(value) = map.get("amount") else {
        return Ok(());
    };
    if matches!(value, json::Value::Null) {
        return Ok(());
    }
    let amount = value.as_str().ok_or_else(|| {
        CodecError::new(
            CodecErrorKind::InvalidArgument,
            format!("{context}.amount must be a canonical Quantity string"),
        )
    })?;
    parse_canonical_quantity_text(amount, &format!("{context}.amount")).map(|_| ())
}

fn canonicalize_hex32_public_input(
    map: &mut json::Map,
    key: &str,
    label: &str,
    context: &str,
) -> CodecResult<()> {
    let Some(value) = map.get_mut(key) else {
        return Ok(());
    };
    if matches!(value, json::Value::Null) {
        return Ok(());
    }
    let raw = value.as_str().ok_or_else(|| {
        CodecError::new(
            CodecErrorKind::InvalidArgument,
            format!("{context}.{label} must be 32-byte hex"),
        )
    })?;
    let canonical = canonicalize_hex32_value(raw).ok_or_else(|| {
        CodecError::new(
            CodecErrorKind::InvalidArgument,
            format!("{context}.{label} must be 32-byte hex"),
        )
    })?;
    *value = json::Value::String(canonical);
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

fn zk_hint_present(map: &json::Map, key: &str) -> bool {
    map.get(key)
        .is_some_and(|value| !matches!(value, json::Value::Null))
}

fn parse_u64_value(value: json::Value, context: &str) -> CodecResult<u64> {
    match value {
        json::Value::Number(number) => number.as_u64().ok_or_else(|| {
            CodecError::new(
                CodecErrorKind::InvalidArgument,
                format!("{context} must be an unsigned integer"),
            )
        }),
        json::Value::String(s) => s.parse::<u64>().map_err(|err| {
            CodecError::new(
                CodecErrorKind::InvalidArgument,
                format!("{context} must be an unsigned integer string: {err}"),
            )
        }),
        other => Err(CodecError::new(
            CodecErrorKind::InvalidArgument,
            format!("{context} must be an unsigned integer (found {other:?})"),
        )),
    }
}

fn remove_case_insensitive(map: &mut json::Map, key: &str) -> Option<json::Value> {
    map.remove(key)
        .or_else(|| map.remove(&key.to_ascii_lowercase()))
        .or_else(|| map.remove(&key.to_ascii_uppercase()))
}

fn parse_canonical_quantity_text(source: &str, context: &str) -> CodecResult<Quantity> {
    let quantity = Quantity::from_str(source).map_err(|err| {
        CodecError::new(
            CodecErrorKind::InvalidArgument,
            format!("{context} must be canonical non-negative Quantity text: {err}"),
        )
    })?;
    if quantity.to_string() != source {
        return Err(CodecError::new(
            CodecErrorKind::InvalidArgument,
            format!("{context} must use canonical Quantity text"),
        ));
    }
    Ok(quantity)
}

fn parse_canonical_quantity_value(value: json::Value, context: &str) -> CodecResult<Quantity> {
    let json::Value::String(source) = value else {
        return Err(CodecError::new(
            CodecErrorKind::InvalidArgument,
            format!("{context} must be a canonical Quantity string"),
        ));
    };
    parse_canonical_quantity_text(&source, context)
}

/// Require exactly the named JSON fields, rejecting missing and unknown fields.
///
/// # Errors
///
/// Returns a [`CodecErrorKind::InvalidArgument`] error listing the missing and
/// unexpected fields when `fields` does not contain exactly `expected`.
pub fn require_exact_json_fields(
    fields: &json::Map,
    expected: &[&str],
    context: &str,
) -> CodecResult<()> {
    let missing = expected
        .iter()
        .copied()
        .filter(|key| !fields.contains_key(*key))
        .collect::<Vec<_>>();
    let unexpected = fields
        .keys()
        .filter(|key| !expected.contains(&key.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if missing.is_empty() && unexpected.is_empty() {
        return Ok(());
    }
    Err(CodecError::new(
        CodecErrorKind::InvalidArgument,
        format!(
            "{context} must contain exactly [{}]; missing [{}], unexpected [{}]",
            expected.join(", "),
            missing.join(", "),
            unexpected.join(", ")
        ),
    ))
}

/// Parse the complete, strict validation fee policy JSON contract.
///
/// # Errors
///
/// Returns an error when the policy, its payout binding or any recipient is not an
/// object with exactly its canonical fields, or when typed decoding fails.
pub fn validation_fee_policy_from_json_value(
    value: json::Value,
) -> CodecResult<ValidationFeePolicyV1> {
    const POLICY_FIELDS: &[&str] = &[
        "schema_version",
        "network_id",
        "policy_version",
        "previous_policy_hash",
        "ds_asset_id",
        "ds_scale",
        "retail_schedule",
        "effective_from_ms",
        "notice_published_at_ms",
        "fee",
        "treasury_account_id",
        "charging_mode",
        "exemption_classes",
        "reward_custody",
    ];
    const REWARD_CUSTODY_FIELDS: &[&str] = &[
        "contract_address",
        "treasury_account_id",
        "ds_asset_id",
        "xor_asset_id",
        "reward_pool_account_id",
        "validator_lane_id",
    ];
    let json::Value::Object(fields) = &value else {
        return Err(CodecError::new(
            CodecErrorKind::InvalidArgument,
            "validation-fee policy must be an object",
        ));
    };
    require_exact_json_fields(fields, POLICY_FIELDS, "validation-fee policy")?;
    let Some(json::Value::Object(custody_fields)) = fields.get("reward_custody") else {
        return Err(CodecError::new(
            CodecErrorKind::InvalidArgument,
            "validation-fee policy.reward_custody must be an object",
        ));
    };
    require_exact_json_fields(
        custody_fields,
        REWARD_CUSTODY_FIELDS,
        "validation-fee policy.reward_custody",
    )?;
    json::from_value(value).map_err(codec_error)
}

/// Validate first-release fee policy invariants.
///
/// # Errors
///
/// Returns an invalid-argument error when the policy violates a first-release invariant.
pub fn validate_validation_fee_policy_proposal(policy: &ValidationFeePolicyV1) -> CodecResult<()> {
    if let Some(reason) = policy.policy_invariant_error() {
        return Err(CodecError::new(
            CodecErrorKind::InvalidArgument,
            format!("invalid validation-fee policy: {reason}"),
        ));
    }
    Ok(())
}

fn validation_fee_policy_instruction_from_json(value: json::Value) -> CodecResult<InstructionBox> {
    const INSTRUCTION_FIELDS: &[&str] = &["policy"];
    let json::Value::Object(mut fields) = value else {
        return Err(CodecError::new(
            CodecErrorKind::InvalidArgument,
            "ProposeValidationFeePolicy must be an object",
        ));
    };
    require_exact_json_fields(&fields, INSTRUCTION_FIELDS, "ProposeValidationFeePolicy")?;
    let policy = validation_fee_policy_from_json_value(required_value(
        &mut fields,
        "policy",
        "ProposeValidationFeePolicy",
    )?)?;
    validate_validation_fee_policy_proposal(&policy)?;
    Ok(ProposeValidationFeePolicy { policy }.into())
}

/// Parse instruction JSON through the strict native instruction adapter.
///
/// # Errors
///
/// Returns an error when the payload is not valid JSON or does not satisfy a strict
/// instruction contract.
pub fn instruction_from_json(payload: &str) -> CodecResult<InstructionBox> {
    let value: json::Value = json::from_json(payload).map_err(codec_error)?;
    value_to_instruction(value)
}

/// Admit the exact native `TransferAssetBatch` JSON rendered by [`instruction_to_json_value`].
///
/// The settlement `mode` and every entry's `leg_id` are part of the native instruction,
/// so both are required rather than defaulted or re-derived.
fn transfer_asset_batch_from_json(value: json::Value) -> CodecResult<InstructionBox> {
    let json::Value::Object(mut fields) = value else {
        return Err(CodecError::new(
            CodecErrorKind::InvalidArgument,
            "TransferAssetBatch payload must be an object",
        ));
    };
    let mode_value = required_value(&mut fields, "mode", "TransferAssetBatch")?;
    let entries_value = required_value(&mut fields, "entries", "TransferAssetBatch")?;
    if !fields.is_empty() {
        return Err(CodecError::new(
            CodecErrorKind::InvalidArgument,
            format!(
                "TransferAssetBatch contains unexpected field(s): {}",
                fields.keys().cloned().collect::<Vec<_>>().join(", ")
            ),
        ));
    }
    let mode: iroha_data_model::isi::BatchMode =
        json::from_value(mode_value).map_err(codec_error)?;
    let json::Value::Array(entry_values) = entries_value else {
        return Err(CodecError::new(
            CodecErrorKind::InvalidArgument,
            "TransferAssetBatch.entries must be an array",
        ));
    };
    let entries = entry_values
        .into_iter()
        .enumerate()
        .map(|(index, entry)| transfer_asset_batch_entry_from_json(entry, index))
        .collect::<CodecResult<Vec<_>>>()?;
    Ok(InstructionBox::from(
        TransferAssetBatch::new(entries).with_mode(mode),
    ))
}

/// Admit one exact `TransferAssetBatch` entry, including its explicit leg identifier.
fn transfer_asset_batch_entry_from_json(
    value: json::Value,
    index: usize,
) -> CodecResult<iroha_data_model::isi::TransferAssetBatchEntry> {
    let context = format!("TransferAssetBatch.entries[{index}]");
    let json::Value::Object(mut entry_fields) = value else {
        return Err(CodecError::new(
            CodecErrorKind::InvalidArgument,
            format!("{context} must be an object"),
        ));
    };
    let leg_id = parse_string_value(
        required_value(&mut entry_fields, "leg_id", &context)?,
        &format!("{context}.leg_id"),
    )?;
    let from = parse_account_id_value(
        required_value(&mut entry_fields, "from", &context)?,
        &format!("{context}.from"),
    )?;
    let to = parse_account_id_value(
        required_value(&mut entry_fields, "to", &context)?,
        &format!("{context}.to"),
    )?;
    let asset_definition_literal = parse_string_value(
        required_value(&mut entry_fields, "asset_definition", &context)?,
        &format!("{context}.asset_definition"),
    )?;
    let asset_definition = AssetDefinitionId::parse_address_literal(&asset_definition_literal)
        .map_err(|err| {
            CodecError::new(
                CodecErrorKind::InvalidArgument,
                format!("invalid {context}.asset_definition: {err}"),
            )
        })?;
    let amount: Quantity = json::from_value(required_value(&mut entry_fields, "amount", &context)?)
        .map_err(codec_error)?;
    if !entry_fields.is_empty() {
        return Err(CodecError::new(
            CodecErrorKind::InvalidArgument,
            format!(
                "{context} contains unexpected field(s): {}",
                entry_fields.keys().cloned().collect::<Vec<_>>().join(", ")
            ),
        ));
    }
    Ok(iroha_data_model::isi::TransferAssetBatchEntry::with_leg_id(
        leg_id,
        from,
        to,
        asset_definition,
        amount,
    ))
}

fn validate_governance_selector_payload(
    payload: Option<&json::Value>,
    field: &str,
    context: &str,
) -> CodecResult<()> {
    let Some(json::Value::Object(fields)) = payload else {
        return Ok(());
    };
    let Some(selector) = fields.get(field) else {
        return Ok(());
    };
    let json::Value::String(selector) = selector else {
        return Err(CodecError::new(
            CodecErrorKind::InvalidArgument,
            format!(
                "{context}.{field} must be 1-128 RFC 3986 unreserved ASCII characters and must not start with a dot"
            ),
        ));
    };
    if !iroha_data_model::governance::is_valid_governance_selector_v1(selector) {
        return Err(CodecError::new(
            CodecErrorKind::InvalidArgument,
            format!(
                "{context}.{field} must be 1-128 RFC 3986 unreserved ASCII characters and must not start with a dot"
            ),
        ));
    }
    Ok(())
}

/// Validate the exact selector fields of governance instruction payloads.
///
/// # Errors
///
/// Returns a [`CodecErrorKind::InvalidArgument`] error when a governance election or
/// referendum selector is not a valid V1 governance selector.
pub fn validate_governance_instruction_selectors(value: &json::Value) -> CodecResult<()> {
    let json::Value::Object(instruction) = value else {
        return Ok(());
    };
    for (variant, field) in [
        ("CastZkBallot", "election_id"),
        ("CastPlainBallot", "referendum_id"),
        ("UpdatePlainConviction", "referendum_id"),
    ] {
        validate_governance_selector_payload(instruction.get(variant), field, variant)?;
    }
    for zk_key in ["zk", "Zk", "ZK"] {
        let Some(json::Value::Object(zk)) = instruction.get(zk_key) else {
            continue;
        };
        for variant in ["CreateElection", "SubmitBallot", "FinalizeElection"] {
            validate_governance_selector_payload(
                zk.get(variant),
                "election_id",
                &format!("{zk_key}.{variant}"),
            )?;
        }
    }
    Ok(())
}

fn instruction_envelope(name: &str, payload: json::Value) -> json::Value {
    let mut outer = json::Map::new();
    outer.insert(name.to_owned(), payload);
    json::Value::Object(outer)
}

fn strict_typed_instruction<T>(payload: &json::Value, name: &str) -> CodecResult<T>
where
    T: json::JsonDeserialize + json::JsonSerialize,
{
    let instruction: T = json::from_value(payload.clone()).map_err(|error| {
        CodecError::new(CodecErrorKind::InvalidArgument, format!("{name}: {error}"))
    })?;
    if json::to_value(&instruction).map_err(codec_error)? != *payload {
        return Err(CodecError::new(
            CodecErrorKind::InvalidArgument,
            format!("{name} must contain exactly its canonical typed JSON fields and values"),
        ));
    }
    Ok(instruction)
}

/// Admit a JSON instruction value with the existing explicit variant checks.
///
/// # Errors
///
/// Returns an error when the value is not an instruction object, names an unsupported
/// instruction, or violates the strict contract of the named instruction.
pub fn value_to_instruction(value: json::Value) -> CodecResult<InstructionBox> {
    // This standalone registration has one exact envelope and a full-width native dataspace
    // field. Refuse additional instruction keys before any other parser can consume them.
    if let json::Value::Object(fields) = &value
        && fields.contains_key("RegisterDataspaceAssetDefinition")
    {
        require_exact_json_fields(
            fields,
            &["RegisterDataspaceAssetDefinition"],
            "direct-dataspace asset registration envelope",
        )?;
        return register_dataspace_asset_definition_from_json(
            fields["RegisterDataspaceAssetDefinition"].clone(),
        );
    }
    // Check the complete artifact envelope before a generic parser can consume
    // a different key (including a null/non-object payload) and hide it.
    if let json::Value::Object(fields) = &value
        && let Some(name) = [
            "RegisterSmartContractCode",
            "RegisterSmartContractBytes",
            "UploadSmartContractCodeChunk",
            "FinalizeSmartContractCodeUpload",
            "CancelSmartContractCodeUpload",
            "RemoveSmartContractBytes",
        ]
        .into_iter()
        .find(|name| fields.contains_key(*name))
    {
        require_exact_json_fields(fields, &[name], "contract artifact instruction envelope")?;
    }
    if let Some(instruction) = plain_governance::from_json(&value) {
        return instruction;
    }
    if let Some(instruction) = retail_daily_limit_instructions::from_json(&value) {
        return instruction;
    }
    if let Some(instruction) = staking_instructions::from_json(&value) {
        return instruction;
    }
    if let Some(instruction) = activation_instructions::from_json(&value) {
        return instruction;
    }
    if let Some(instruction) = lifecycle_instructions::from_json(&value) {
        return instruction;
    }
    if let Some(instruction) = game_instructions::from_json(&value) {
        return instruction;
    }
    if let Some(instruction) = verifying_key_instructions::from_json(&value) {
        return instruction;
    }
    validate_governance_instruction_selectors(&value)?;
    // These instructions carry release-critical JSON contracts. The generic
    // `InstructionBox` decoder may accept data-model defaults and unknown
    // fields, so route these envelopes through explicit strict parsers.
    let requires_explicit_parser = matches!(
        &value,
        json::Value::Object(map)
            if map.contains_key("Register")
                || map.contains_key("Settlement")
                || map.contains_key("CancelSmartContractCodeUpload")
                || map.contains_key("RegisterSmartContractCode")
                || map.contains_key("RegisterSmartContractBytes")
                || map.contains_key("RemoveSmartContractBytes")
                || map.contains_key("CancelAssetLock")
                || map.contains_key("SetAssetTransferAvailability")
                || map.contains_key("SetAssetTransferBlacklist")
                || map.contains_key("SetAssetTransferControl")
                || map.contains_key("ProposeValidationFeePolicy")
    );
    if !requires_explicit_parser
        && let Ok(instruction) = json::from_value::<InstructionBox>(value.clone())
    {
        if plain_governance::is_plain_instruction(&instruction)
            || activation_instructions::is_activation_instruction(&instruction)
            || retail_daily_limit_instructions::is_retail_instruction(&instruction)
            || game_instructions::is_game_instruction(&instruction)
            || verifying_key_instructions::is_verifying_key_instruction(&instruction)
            || lifecycle_instructions::is_lifecycle_instruction(&instruction)
            || staking_instructions::is_staking_instruction(&instruction)
            || instruction.as_any().is::<CancelSmartContractCodeUpload>()
            || instruction.as_any().is::<RegisterSmartContractCode>()
            || instruction.as_any().is::<RegisterSmartContractBytes>()
            || instruction.as_any().is::<RemoveSmartContractBytes>()
            || instruction
                .as_any()
                .is::<RegisterDataspaceAssetDefinition>()
        {
            return Err(CodecError::new(
                CodecErrorKind::InvalidArgument,
                "instruction requires its exact canonical JSON envelope",
            ));
        }
        return Ok(instruction);
    }
    match value {
        json::Value::Object(mut map) => {
            for parse in ENVELOPE_PARSERS {
                if let Some(instruction) = parse(&mut map) {
                    return instruction;
                }
            }
            Err(CodecError::new(
                CodecErrorKind::InvalidArgument,
                "unsupported instruction; refer to Iroha data model instructions for supported variants",
            ))
        }
        _ => Err(CodecError::new(
            CodecErrorKind::InvalidArgument,
            "instruction JSON must be an object",
        )),
    }
}

/// Parser for one precedence-ordered group of strict instruction envelope keys.
type EnvelopeParser = fn(&mut json::Map) -> Option<CodecResult<InstructionBox>>;

/// Strict envelope parsers in their fixed key precedence order.
///
/// Each parser probes its keys in order and returns `None` when none is present.
/// A probed key is removed even when its payload shape is not admitted there, so
/// later parsers and the final diagnostic see only the remaining envelope fields.
const ENVELOPE_PARSERS: [EnvelopeParser; 9] = [
    asset_transfer_control_from_envelope,
    soracloud_instruction_from_envelope,
    settlement_instruction_from_envelope,
    ledger_instruction_from_envelope,
    rwa_instruction_from_envelope,
    kaigi_instruction_from_envelope,
    governance_instruction_from_envelope,
    social_instruction_from_envelope,
    custom_instruction_from_envelope,
];

/// Remove `key` and require that it was the only instruction envelope field.
fn sole_instruction_payload(map: &mut json::Map, key: &str) -> Option<CodecResult<json::Value>> {
    let payload = map.remove(key)?;
    if !map.is_empty() {
        return Some(Err(CodecError::new(
            CodecErrorKind::InvalidArgument,
            format!(
                "{key} instruction envelope contains unexpected field(s): {}",
                map.keys().cloned().collect::<Vec<_>>().join(", ")
            ),
        )));
    }
    Some(Ok(payload))
}

/// Decode a payload whose JSON contract is owned entirely by its native model type.
fn model_instruction_from_json<T>(payload: json::Value) -> CodecResult<InstructionBox>
where
    T: json::JsonDeserialize + Into<InstructionBox>,
{
    let instruction: T = json::from_value(payload).map_err(codec_error)?;
    Ok(instruction.into())
}

/// Asset transfer availability, blacklist and control instructions.
fn asset_transfer_control_from_envelope(
    map: &mut json::Map,
) -> Option<CodecResult<InstructionBox>> {
    if let Some(payload) = sole_instruction_payload(map, "SetAssetTransferAvailability") {
        return Some(payload.and_then(set_asset_transfer_availability_from_json));
    }
    if let Some(payload) = sole_instruction_payload(map, "SetAssetTransferBlacklist") {
        return Some(payload.and_then(set_asset_transfer_blacklist_from_json));
    }
    if let Some(payload) = sole_instruction_payload(map, "SetAssetTransferControl") {
        return Some(payload.and_then(set_asset_transfer_control_from_json));
    }
    None
}

/// Soracloud deployment and shared-lease instructions.
fn soracloud_instruction_from_envelope(map: &mut json::Map) -> Option<CodecResult<InstructionBox>> {
    if let Some(payload) = sole_instruction_payload(map, "DeploySoracloudService") {
        return Some(payload.and_then(
            model_instruction_from_json::<iroha_data_model::isi::soracloud::DeploySoracloudService>,
        ));
    }
    if let Some(payload) = sole_instruction_payload(map, "DeploySoracloudAgentApartment") {
        return Some(payload.and_then(
            model_instruction_from_json::<
                iroha_data_model::isi::soracloud::DeploySoracloudAgentApartment,
            >,
        ));
    }
    if let Some(payload) = sole_instruction_payload(map, "JoinSoracloudHfSharedLease") {
        return Some(payload.and_then(
            model_instruction_from_json::<
                iroha_data_model::isi::soracloud::JoinSoracloudHfSharedLease,
            >,
        ));
    }
    None
}

/// Validation-fee proposals, settlements, batch transfers and asset-lock cancellation.
fn settlement_instruction_from_envelope(
    map: &mut json::Map,
) -> Option<CodecResult<InstructionBox>> {
    if let Some(payload) = sole_instruction_payload(map, "ProposeValidationFeePolicy") {
        return Some(payload.and_then(validation_fee_policy_instruction_from_json));
    }
    if let Some(payload) = sole_instruction_payload(map, "Settlement") {
        return Some(payload.and_then(settlement_instruction_from_json));
    }
    if let Some(batch_value) = map.remove("TransferAssetBatch") {
        return Some(transfer_asset_batch_from_json(batch_value));
    }
    if let Some(payload) = sole_instruction_payload(map, "CancelAssetLock") {
        return Some(payload.and_then(cancel_asset_lock_from_json));
    }
    None
}

/// Code-upload cancellation and the generic ledger instructions.
fn ledger_instruction_from_envelope(map: &mut json::Map) -> Option<CodecResult<InstructionBox>> {
    if let Some(payload) = sole_instruction_payload(map, "CancelSmartContractCodeUpload") {
        return Some(payload.and_then(cancel_smart_contract_code_upload_from_json));
    }
    if let Some(payload) = sole_instruction_payload(map, "Register") {
        return Some(payload.and_then(register_from_json));
    }
    if let Some(parameter_value) = remove_case_insensitive(map, "SetParameter") {
        return Some(set_parameter_from_json(parameter_value));
    }
    if let Some(json::Value::Object(mint_map)) = map.remove("Mint") {
        return Some(mint_from_json(mint_map));
    }
    if let Some(json::Value::Object(unregister_map)) = map.remove("Unregister") {
        return Some(unregister_from_json(unregister_map));
    }
    if let Some(json::Value::Object(burn_map)) = map.remove("Burn") {
        return Some(burn_from_json(burn_map));
    }
    if let Some(json::Value::Object(execute_fields)) = map.remove("ExecuteTrigger") {
        return Some(execute_trigger_from_json(execute_fields));
    }
    if let Some(json::Value::Object(transfer_map)) = map.remove("Transfer") {
        return Some(transfer_from_json(transfer_map));
    }
    if let Some(json::Value::Object(grant_map)) = map.remove("Grant") {
        return Some(grant_from_json(grant_map));
    }
    if let Some(json::Value::Object(fields)) = map.remove("SetAssetDefinitionAlias") {
        return Some(set_asset_definition_alias_from_json(fields));
    }
    None
}

/// RWA instructions, with account and NFT `SetKeyValue` kept at its fixed precedence.
fn rwa_instruction_from_envelope(map: &mut json::Map) -> Option<CodecResult<InstructionBox>> {
    if let Some(json::Value::Object(fields)) = map.remove("RegisterRwa") {
        return Some(register_rwa_from_json(fields));
    }
    if let Some(json::Value::Object(fields)) = map.remove("TransferRwa") {
        return Some(transfer_rwa_from_json(fields));
    }
    if let Some(json::Value::Object(fields)) = map.remove("MergeRwas") {
        return Some(merge_rwas_from_json(fields));
    }
    if let Some(json::Value::Object(fields)) = map.remove("RedeemRwa") {
        return Some(redeem_rwa_from_json(fields));
    }
    if let Some(json::Value::Object(fields)) = map.remove("FreezeRwa") {
        return Some(freeze_rwa_from_json(fields));
    }
    if let Some(json::Value::Object(fields)) = map.remove("UnfreezeRwa") {
        return Some(unfreeze_rwa_from_json(fields));
    }
    if let Some(json::Value::Object(fields)) = map.remove("HoldRwa") {
        return Some(hold_rwa_from_json(fields));
    }
    if let Some(json::Value::Object(fields)) = map.remove("ReleaseRwa") {
        return Some(release_rwa_from_json(fields));
    }
    if let Some(json::Value::Object(fields)) = map.remove("ForceTransferRwa") {
        return Some(force_transfer_rwa_from_json(fields));
    }
    if let Some(json::Value::Object(fields)) = map.remove("SetRwaControls") {
        return Some(set_rwa_controls_from_json(fields));
    }
    if let Some(json::Value::Object(fields)) = map.remove("SetRwaKeyValue") {
        return Some(set_rwa_key_value_from_json(fields));
    }
    if let Some(json::Value::Object(variants)) = map.remove("SetKeyValue") {
        return Some(set_key_value_from_json(variants));
    }
    if let Some(json::Value::Object(fields)) = map.remove("RemoveRwaKeyValue") {
        return Some(remove_rwa_key_value_from_json(fields));
    }
    None
}

/// Kaigi call and relay instructions.
fn kaigi_instruction_from_envelope(map: &mut json::Map) -> Option<CodecResult<InstructionBox>> {
    if let Some(json::Value::Object(kaigi_map)) = map.remove("Kaigi") {
        return Some(kaigi_from_json(kaigi_map));
    }
    None
}

/// Governance proposals, ballots, citizenship and smart-contract code instructions.
fn governance_instruction_from_envelope(
    map: &mut json::Map,
) -> Option<CodecResult<InstructionBox>> {
    if let Some(json::Value::Object(fields)) = map.remove("ProposeDeployContract") {
        return Some(propose_deploy_contract_from_json(fields));
    }
    if let Some(json::Value::Object(fields)) = map.remove("CastZkBallot") {
        return Some(cast_zk_ballot_from_json(fields));
    }
    if let Some(json::Value::Object(fields)) = map.remove("RegisterCitizen") {
        return Some(register_citizen_from_json(fields));
    }
    if let Some(json::Value::Object(fields)) = map.remove("SubmitAgendaProposal") {
        return Some(submit_agenda_proposal_from_json(fields));
    }
    if let Some(json::Value::Object(fields)) = map.remove("RegisterSmartContractCode") {
        return Some(register_smart_contract_code_from_json(map, fields));
    }
    if let Some(json::Value::Object(fields)) = map.remove("RegisterSmartContractBytes") {
        return Some(register_smart_contract_bytes_from_json(map, fields));
    }
    if let Some(json::Value::Object(fields)) = map.remove("RemoveSmartContractBytes") {
        return Some(remove_smart_contract_bytes_from_json(map, fields));
    }
    None
}

/// Social reward and escrow instructions.
fn social_instruction_from_envelope(map: &mut json::Map) -> Option<CodecResult<InstructionBox>> {
    if let Some(value) = map.remove("ClaimTwitterFollowReward") {
        return Some(claim_twitter_follow_reward_from_json(value));
    }
    if let Some(value) = map.remove("SendToTwitter") {
        return Some(send_to_twitter_from_json(value));
    }
    if let Some(value) = map.remove("CancelTwitterEscrow") {
        return Some(cancel_twitter_escrow_from_json(value));
    }
    None
}

/// Case-insensitive `Custom`, `Multisig` and `Zk` envelopes.
fn custom_instruction_from_envelope(map: &mut json::Map) -> Option<CodecResult<InstructionBox>> {
    if let Some(custom_value) = remove_case_insensitive(map, "Custom") {
        return Some(custom_from_json(custom_value));
    }
    if let Some(multisig_value) = remove_case_insensitive(map, "Multisig") {
        return Some(multisig_from_json(multisig_value));
    }
    if let Some(propose_value) = remove_case_insensitive(map, "MultisigPropose") {
        return Some(multisig_propose_from_json(propose_value));
    }
    if let Some(approve_value) = remove_case_insensitive(map, "MultisigApprove") {
        return Some(multisig_approve_from_json(approve_value));
    }
    if let Some(cancel_value) = remove_case_insensitive(map, "MultisigCancel") {
        return Some(multisig_cancel_from_json(cancel_value));
    }
    if let Some(register_value) = remove_case_insensitive(map, "MultisigRegister") {
        return Some(multisig_register_from_json(register_value));
    }
    if let Some(zk_value) = remove_case_insensitive(map, "Zk") {
        return Some(zk_from_json(zk_value));
    }
    None
}

/// Admit the strict `SetAssetTransferAvailability` instruction payload.
fn set_asset_transfer_availability_from_json(payload: json::Value) -> CodecResult<InstructionBox> {
    let json::Value::Object(mut fields) = payload else {
        return Err(CodecError::new(
            CodecErrorKind::InvalidArgument,
            "SetAssetTransferAvailability must be an object",
        ));
    };
    let account_id = parse_account_id_value(
        required_value(&mut fields, "account_id", "SetAssetTransferAvailability")?,
        "SetAssetTransferAvailability.account_id",
    )?;
    let asset_definition_literal = parse_string_value(
        required_value(
            &mut fields,
            "asset_definition_id",
            "SetAssetTransferAvailability",
        )?,
        "SetAssetTransferAvailability.asset_definition_id",
    )?;
    let asset_definition_id = AssetDefinitionId::parse_address_literal(&asset_definition_literal)
        .map_err(|error| {
        CodecError::new(
            CodecErrorKind::InvalidArgument,
            format!("invalid SetAssetTransferAvailability.asset_definition_id: {error}"),
        )
    })?;
    let expected_revision = parse_u64_value(
        required_value(
            &mut fields,
            "expected_revision",
            "SetAssetTransferAvailability",
        )?,
        "SetAssetTransferAvailability.expected_revision",
    )?;
    let parse_availability = |value: json::Value,
                              context: &str|
     -> CodecResult<AssetTransferAvailability> {
        match value {
            json::Value::String(value) if value == "Enabled" => {
                Ok(AssetTransferAvailability::Enabled)
            }
            json::Value::String(value) if value == "Disabled" => {
                Ok(AssetTransferAvailability::Disabled)
            }
            other => Err(CodecError::new(
                CodecErrorKind::InvalidArgument,
                format!("{context} must be exactly \"Enabled\" or \"Disabled\" (found {other:?})"),
            )),
        }
    };
    let incoming = parse_availability(
        required_value(&mut fields, "incoming", "SetAssetTransferAvailability")?,
        "SetAssetTransferAvailability.incoming",
    )?;
    let outgoing = parse_availability(
        required_value(&mut fields, "outgoing", "SetAssetTransferAvailability")?,
        "SetAssetTransferAvailability.outgoing",
    )?;
    let reason = match fields.remove("reason") {
        None | Some(json::Value::Null) => None,
        Some(json::Value::String(value)) if !value.is_empty() && value.trim() == value => {
            Some(value)
        }
        Some(other) => {
            return Err(CodecError::new(
                CodecErrorKind::InvalidArgument,
                format!(
                    "SetAssetTransferAvailability.reason must be non-empty exact text or null (found {other:?})"
                ),
            ));
        }
    };
    validate_asset_transfer_availability_reason(reason.as_deref())
        .map_err(|error| CodecError::new(CodecErrorKind::InvalidArgument, error.to_string()))?;
    if !fields.is_empty() {
        return Err(CodecError::new(
            CodecErrorKind::InvalidArgument,
            format!(
                "SetAssetTransferAvailability contains unexpected field(s): {}",
                fields.keys().cloned().collect::<Vec<_>>().join(", ")
            ),
        ));
    }
    Ok(SetAssetTransferAvailability::new(
        account_id,
        asset_definition_id,
        expected_revision,
        incoming,
        outgoing,
        reason,
    )
    .into())
}

/// Admit the strict `SetAssetTransferBlacklist` instruction payload.
fn set_asset_transfer_blacklist_from_json(payload: json::Value) -> CodecResult<InstructionBox> {
    let json::Value::Object(mut fields) = payload else {
        return Err(CodecError::new(
            CodecErrorKind::InvalidArgument,
            "SetAssetTransferBlacklist must be an object",
        ));
    };
    require_exact_json_fields(
        &fields,
        &["account_id", "asset_definition_id", "blacklisted"],
        "SetAssetTransferBlacklist",
    )?;
    let account_id = parse_account_id_value(
        required_value(&mut fields, "account_id", "SetAssetTransferBlacklist")?,
        "SetAssetTransferBlacklist.account_id",
    )?;
    let asset_definition_literal = parse_string_value(
        required_value(
            &mut fields,
            "asset_definition_id",
            "SetAssetTransferBlacklist",
        )?,
        "SetAssetTransferBlacklist.asset_definition_id",
    )?;
    let asset_definition_id = AssetDefinitionId::parse_address_literal(&asset_definition_literal)
        .map_err(|error| {
        CodecError::new(
            CodecErrorKind::InvalidArgument,
            format!("invalid SetAssetTransferBlacklist.asset_definition_id: {error}"),
        )
    })?;
    let blacklisted = match required_value(&mut fields, "blacklisted", "SetAssetTransferBlacklist")?
    {
        json::Value::Bool(value) => value,
        other => {
            return Err(CodecError::new(
                CodecErrorKind::InvalidArgument,
                format!(
                    "SetAssetTransferBlacklist.blacklisted must be a boolean (found {other:?})"
                ),
            ));
        }
    };
    Ok(SetAssetTransferBlacklist::new(account_id, asset_definition_id, blacklisted).into())
}

/// Admit the strict `SetAssetTransferControl` instruction payload.
fn set_asset_transfer_control_from_json(payload: json::Value) -> CodecResult<InstructionBox> {
    let json::Value::Object(mut fields) = payload else {
        return Err(CodecError::new(
            CodecErrorKind::InvalidArgument,
            "SetAssetTransferControl must be an object",
        ));
    };
    require_exact_json_fields(
        &fields,
        &["account_id", "asset_definition_id", "limits"],
        "SetAssetTransferControl",
    )?;
    let account_id = parse_account_id_value(
        required_value(&mut fields, "account_id", "SetAssetTransferControl")?,
        "SetAssetTransferControl.account_id",
    )?;
    let asset_definition_literal = parse_string_value(
        required_value(
            &mut fields,
            "asset_definition_id",
            "SetAssetTransferControl",
        )?,
        "SetAssetTransferControl.asset_definition_id",
    )?;
    let asset_definition_id = AssetDefinitionId::parse_address_literal(&asset_definition_literal)
        .map_err(|error| {
        CodecError::new(
            CodecErrorKind::InvalidArgument,
            format!("invalid SetAssetTransferControl.asset_definition_id: {error}"),
        )
    })?;
    let limits_value = required_value(&mut fields, "limits", "SetAssetTransferControl")?;
    let json::Value::Array(limit_values) = limits_value else {
        return Err(CodecError::new(
            CodecErrorKind::InvalidArgument,
            "SetAssetTransferControl.limits must be an array",
        ));
    };
    let mut limits = Vec::with_capacity(limit_values.len());
    for (index, value) in limit_values.into_iter().enumerate() {
        let context = format!("SetAssetTransferControl.limits[{index}]");
        let json::Value::Object(mut limit_fields) = value else {
            return Err(CodecError::new(
                CodecErrorKind::InvalidArgument,
                format!("{context} must be an object"),
            ));
        };
        require_exact_json_fields(&limit_fields, &["window", "cap_amount"], &context)?;
        let window = match required_value(&mut limit_fields, "window", &context)? {
            json::Value::String(value) if value == "Day" => AssetTransferControlWindow::Day,
            json::Value::String(value) if value == "Week" => AssetTransferControlWindow::Week,
            json::Value::String(value) if value == "Month" => AssetTransferControlWindow::Month,
            other => {
                return Err(CodecError::new(
                    CodecErrorKind::InvalidArgument,
                    format!(
                        "{context}.window must be exactly \"Day\", \"Week\", or \"Month\" (found {other:?})"
                    ),
                ));
            }
        };
        if limits
            .iter()
            .any(|limit: &AssetTransferLimit| limit.window == window)
        {
            return Err(CodecError::new(
                CodecErrorKind::InvalidArgument,
                format!("{context}.window duplicates {window}"),
            ));
        }
        let cap_amount = match required_value(&mut limit_fields, "cap_amount", &context)? {
            json::Value::Null => None,
            value => Some(parse_canonical_quantity_value(
                value,
                &format!("{context}.cap_amount"),
            )?),
        };
        limits.push(AssetTransferLimit { window, cap_amount });
    }
    Ok(SetAssetTransferControl::new(account_id, asset_definition_id, limits).into())
}

/// Admit the strict `CancelAssetLock` instruction payload.
fn cancel_asset_lock_from_json(cancel_value: json::Value) -> CodecResult<InstructionBox> {
    exact_json_object_fields(
        &cancel_value,
        &["escrow_id", "expected_remaining_amount"],
        "CancelAssetLock",
    )?;
    let json::Value::Object(mut fields) = cancel_value else {
        unreachable!("exact_json_object_fields accepted an object");
    };
    let escrow_id = EscrowId::new(parse_canonical_hash_value(
        required_value(&mut fields, "escrow_id", "CancelAssetLock")?,
        "CancelAssetLock.escrow_id",
    )?);
    let expected_remaining_amount = parse_canonical_quantity_value(
        required_value(&mut fields, "expected_remaining_amount", "CancelAssetLock")?,
        "CancelAssetLock.expected_remaining_amount",
    )?;
    if expected_remaining_amount.is_zero() {
        return Err(CodecError::new(
            CodecErrorKind::InvalidArgument,
            "CancelAssetLock.expected_remaining_amount must be positive",
        ));
    }
    Ok(CancelAssetLock::new(escrow_id, expected_remaining_amount).into())
}

/// Admit the strict `CancelSmartContractCodeUpload` instruction payload.
fn cancel_smart_contract_code_upload_from_json(
    cancel_value: json::Value,
) -> CodecResult<InstructionBox> {
    let json::Value::Object(mut fields) = cancel_value else {
        return Err(CodecError::new(
            CodecErrorKind::InvalidArgument,
            "CancelSmartContractCodeUpload must be an object",
        ));
    };
    let artifact_id = lifecycle_instructions::parse_artifact_id(
        required_value(&mut fields, "artifact_id", "CancelSmartContractCodeUpload")?,
        "CancelSmartContractCodeUpload.artifact_id",
    )?;
    if !fields.is_empty() {
        return Err(CodecError::new(
            CodecErrorKind::InvalidArgument,
            format!(
                "CancelSmartContractCodeUpload contains unexpected field(s): {}",
                fields.keys().cloned().collect::<Vec<_>>().join(", ")
            ),
        ));
    }
    Ok(InstructionBox::from(CancelSmartContractCodeUpload {
        artifact_id,
    }))
}

/// Admit the exact native fields of a direct-dataspace registration.
fn register_dataspace_asset_definition_from_json(
    value: json::Value,
) -> CodecResult<InstructionBox> {
    let instruction: RegisterDataspaceAssetDefinition =
        strict_typed_instruction(&value, "RegisterDataspaceAssetDefinition")?;
    instruction
        .validate()
        .map_err(|error| CodecError::new(CodecErrorKind::InvalidArgument, error.to_string()))?;
    Ok(instruction.into())
}

/// Admit the strict `Register` instruction payload.
fn register_from_json(register_value: json::Value) -> CodecResult<InstructionBox> {
    let json::Value::Object(mut register_map) = register_value else {
        return Err(CodecError::new(
            CodecErrorKind::InvalidArgument,
            "Register instruction must be an object containing exactly one variant",
        ));
    };
    if register_map.len() != 1 {
        return Err(CodecError::new(
            CodecErrorKind::InvalidArgument,
            "Register instruction must contain exactly one variant",
        ));
    }
    if let Some(domain_value) = register_map.remove("Domain") {
        let new_domain: NewDomain = json::from_value(domain_value).map_err(codec_error)?;
        let register_box = RegisterBox::Domain(Register::<Domain>::domain(new_domain));
        return Ok(InstructionBox::from(register_box));
    }
    if let Some(account_value) = register_map.remove("Account") {
        let new_account: NewAccount = json::from_value(account_value).map_err(|error| {
            CodecError::new(
                CodecErrorKind::InvalidArgument,
                format!("invalid Register.Account: {error}"),
            )
        })?;
        let register_box = RegisterBox::Account(Register::<Account>::account(new_account));
        return Ok(InstructionBox::from(register_box));
    }
    if let Some(asset_value) = register_map.remove("AssetDefinition") {
        let new_asset: NewAssetDefinition = json::from_value(asset_value).map_err(codec_error)?;
        let register_box =
            RegisterBox::AssetDefinition(Register::<AssetDefinition>::asset_definition(new_asset));
        return Ok(InstructionBox::from(register_box));
    }
    if let Some(nft_value) = register_map.remove("Nft") {
        let new_nft: NewNft = json::from_value(nft_value).map_err(codec_error)?;
        let register_box = RegisterBox::Nft(Register::<Nft>::nft(new_nft));
        return Ok(InstructionBox::from(register_box));
    }
    if let Some(role_value) = register_map.remove("Role") {
        let new_role: NewRole = json::from_value(role_value).map_err(codec_error)?;
        let register_box = RegisterBox::Role(Register::<Role>::role(new_role));
        return Ok(InstructionBox::from(register_box));
    }
    if let Some(trigger_value) = register_map.remove("Trigger") {
        let json::Value::Object(mut trigger_fields) = trigger_value else {
            return Err(CodecError::new(
                CodecErrorKind::InvalidArgument,
                "Register.Trigger must be an object with exact id and action fields",
            ));
        };
        let trigger_id: TriggerId = json::from_value(required_value(
            &mut trigger_fields,
            "id",
            "Register.Trigger",
        )?)
        .map_err(codec_error)?;
        let action: Action = json::from_value(required_value(
            &mut trigger_fields,
            "action",
            "Register.Trigger",
        )?)
        .map_err(codec_error)?;
        if !trigger_fields.is_empty() {
            return Err(CodecError::new(
                CodecErrorKind::InvalidArgument,
                format!(
                    "Register.Trigger contains unexpected field(s): {}",
                    trigger_fields
                        .keys()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ));
        }
        let trigger = Trigger::new(trigger_id, action);
        let register_box = RegisterBox::Trigger(Register::<Trigger>::trigger(trigger));
        return Ok(InstructionBox::from(register_box));
    }
    if let Some(peer_value) = register_map.remove("Peer") {
        let peer_registration: RegisterPeerWithPop =
            json::from_value(peer_value).map_err(codec_error)?;
        let register_box = RegisterBox::Peer(peer_registration);
        return Ok(InstructionBox::from(register_box));
    }
    Err(CodecError::new(
        CodecErrorKind::InvalidArgument,
        "unsupported Register instruction variant",
    ))
}

/// Admit the strict `SetParameter` instruction payload.
fn set_parameter_from_json(parameter_value: json::Value) -> CodecResult<InstructionBox> {
    let parameter = json::from_value::<Parameter>(parameter_value.clone())
        .or_else(|_| json::from_value::<CustomParameter>(parameter_value).map(Parameter::Custom))
        .map_err(codec_error)?;
    Ok(InstructionBox::from(SetParameter::new(parameter)))
}

/// Admit the strict `Mint` instruction payload.
fn mint_from_json(mut mint_map: json::Map) -> CodecResult<InstructionBox> {
    if let Some(json::Value::Object(mut asset_fields)) = mint_map.remove("Asset") {
        let quantity_value = asset_fields.remove("object").ok_or_else(|| {
            CodecError::new(
                CodecErrorKind::InvalidArgument,
                "Mint.Asset.object field missing",
            )
        })?;
        let destination_value = asset_fields.remove("destination").ok_or_else(|| {
            CodecError::new(
                CodecErrorKind::InvalidArgument,
                "Mint.Asset.destination field missing",
            )
        })?;
        let quantity: Quantity = json::from_value(quantity_value).map_err(codec_error)?;
        let destination: AssetId = json::from_value(destination_value).map_err(codec_error)?;
        let mint = Mint::asset_quantity(quantity, destination);
        return Ok(InstructionBox::from(MintBox::Asset(mint)));
    }
    if let Some(json::Value::Object(mut trigger_fields)) = mint_map.remove("TriggerRepetitions") {
        let repetitions_value = trigger_fields.remove("object").ok_or_else(|| {
            CodecError::new(
                CodecErrorKind::InvalidArgument,
                "Mint.TriggerRepetitions.object field missing",
            )
        })?;
        let destination_value = trigger_fields.remove("destination").ok_or_else(|| {
            CodecError::new(
                CodecErrorKind::InvalidArgument,
                "Mint.TriggerRepetitions.destination field missing",
            )
        })?;
        let repetitions: u32 = json::from_value(repetitions_value).map_err(codec_error)?;
        let trigger_id: TriggerId = json::from_value(destination_value).map_err(codec_error)?;
        let mint = Mint::trigger_repetitions(repetitions, trigger_id);
        return Ok(InstructionBox::from(MintBox::TriggerRepetitions(mint)));
    }
    Err(CodecError::new(
        CodecErrorKind::InvalidArgument,
        "unsupported Mint instruction variant; expected keys: Asset or TriggerRepetitions",
    ))
}

/// Admit the strict `Unregister` instruction payload.
fn unregister_from_json(mut unregister_map: json::Map) -> CodecResult<InstructionBox> {
    if let Some(peer_value) = unregister_map.remove("Peer") {
        let peer_id: PeerId = json::from_value(peer_value).map_err(codec_error)?;
        let unregister_box = UnregisterBox::Peer(Unregister::<Peer>::peer(peer_id));
        return Ok(InstructionBox::from(unregister_box));
    }
    if let Some(domain_value) = unregister_map.remove("Domain") {
        let domain_id: DomainId = json::from_value(domain_value).map_err(codec_error)?;
        let unregister_box = UnregisterBox::Domain(Unregister::<Domain>::domain(domain_id));
        return Ok(InstructionBox::from(unregister_box));
    }
    if let Some(account_value) = unregister_map.remove("Account") {
        let account_id = parse_account_id_value(account_value, "Unregister.Account")?;
        let unregister_box = UnregisterBox::Account(Unregister::<Account>::account(account_id));
        return Ok(InstructionBox::from(unregister_box));
    }
    if let Some(asset_value) = unregister_map.remove("AssetDefinition") {
        let definition_id: AssetDefinitionId =
            json::from_value(asset_value).map_err(codec_error)?;
        let unregister_box = UnregisterBox::AssetDefinition(
            Unregister::<AssetDefinition>::asset_definition(definition_id),
        );
        return Ok(InstructionBox::from(unregister_box));
    }
    if let Some(nft_value) = unregister_map.remove("Nft") {
        let nft_id: NftId = json::from_value(nft_value).map_err(codec_error)?;
        let unregister_box = UnregisterBox::Nft(Unregister::<Nft>::nft(nft_id));
        return Ok(InstructionBox::from(unregister_box));
    }
    if let Some(role_value) = unregister_map.remove("Role") {
        let role_id: RoleId = json::from_value(role_value).map_err(codec_error)?;
        let unregister_box = UnregisterBox::Role(Unregister::<Role>::role(role_id));
        return Ok(InstructionBox::from(unregister_box));
    }
    if let Some(trigger_value) = unregister_map.remove("Trigger") {
        let trigger_id: TriggerId = json::from_value(trigger_value).map_err(codec_error)?;
        let unregister_box = UnregisterBox::Trigger(Unregister::<Trigger>::trigger(trigger_id));
        return Ok(InstructionBox::from(unregister_box));
    }
    Err(CodecError::new(
        CodecErrorKind::InvalidArgument,
        "unsupported Unregister instruction variant; expected keys: Peer, Domain, Account, AssetDefinition, Nft, Role, Trigger",
    ))
}

/// Admit the strict `Burn` instruction payload.
fn burn_from_json(mut burn_map: json::Map) -> CodecResult<InstructionBox> {
    if let Some(json::Value::Object(mut asset_fields)) = burn_map.remove("Asset") {
        let quantity_value = asset_fields.remove("object").ok_or_else(|| {
            CodecError::new(
                CodecErrorKind::InvalidArgument,
                "Burn.Asset.object field missing",
            )
        })?;
        let destination_value = asset_fields.remove("destination").ok_or_else(|| {
            CodecError::new(
                CodecErrorKind::InvalidArgument,
                "Burn.Asset.destination field missing",
            )
        })?;
        let quantity: Quantity = json::from_value(quantity_value).map_err(codec_error)?;
        let asset_id: AssetId = json::from_value(destination_value).map_err(codec_error)?;
        let burn = Burn::asset_quantity(quantity, asset_id);
        return Ok(InstructionBox::from(BurnBox::Asset(burn)));
    }
    if let Some(json::Value::Object(mut trigger_fields)) = burn_map.remove("TriggerRepetitions") {
        let repetitions_value = trigger_fields.remove("object").ok_or_else(|| {
            CodecError::new(
                CodecErrorKind::InvalidArgument,
                "Burn.TriggerRepetitions.object field missing",
            )
        })?;
        let destination_value = trigger_fields.remove("destination").ok_or_else(|| {
            CodecError::new(
                CodecErrorKind::InvalidArgument,
                "Burn.TriggerRepetitions.destination field missing",
            )
        })?;
        let repetitions: u32 = json::from_value(repetitions_value).map_err(codec_error)?;
        let trigger_id: TriggerId = json::from_value(destination_value).map_err(codec_error)?;
        let burn = Burn::trigger_repetitions(repetitions, trigger_id);
        return Ok(InstructionBox::from(BurnBox::TriggerRepetitions(burn)));
    }
    Err(CodecError::new(
        CodecErrorKind::InvalidArgument,
        "unsupported Burn instruction variant; expected keys: Asset or TriggerRepetitions",
    ))
}

/// Admit the strict `ExecuteTrigger` instruction payload.
fn execute_trigger_from_json(mut execute_fields: json::Map) -> CodecResult<InstructionBox> {
    let trigger: TriggerId = json::from_value(required_value(
        &mut execute_fields,
        "trigger",
        "ExecuteTrigger",
    )?)
    .map_err(codec_error)?;
    let args = execute_fields
        .remove("args")
        .map(Json::from)
        .unwrap_or_default();
    Ok(InstructionBox::from(ExecuteTrigger { trigger, args }))
}

/// Admit the strict `Transfer` instruction payload.
fn transfer_from_json(mut transfer_map: json::Map) -> CodecResult<InstructionBox> {
    if let Some(json::Value::Object(asset_fields)) = transfer_map.remove("Asset") {
        return transfer_asset_from_json(asset_fields);
    }
    if let Some(json::Value::Object(domain_fields)) = transfer_map.remove("Domain") {
        return transfer_domain_from_json(domain_fields);
    }
    if let Some(json::Value::Object(definition_fields)) = transfer_map.remove("AssetDefinition") {
        return transfer_asset_definition_from_json(definition_fields);
    }
    if let Some(json::Value::Object(nft_fields)) = transfer_map.remove("Nft") {
        return transfer_nft_from_json(nft_fields);
    }
    Err(CodecError::new(
        CodecErrorKind::InvalidArgument,
        "unsupported Transfer instruction variant; expected keys: Asset, Domain, AssetDefinition, or Nft",
    ))
}

/// Admit the strict `Transfer.Asset` payload.
fn transfer_asset_from_json(mut asset_fields: json::Map) -> CodecResult<InstructionBox> {
    let source_value = asset_fields.remove("source").ok_or_else(|| {
        CodecError::new(
            CodecErrorKind::InvalidArgument,
            "Transfer.Asset.source field missing",
        )
    })?;
    let quantity_value = asset_fields.remove("object").ok_or_else(|| {
        CodecError::new(
            CodecErrorKind::InvalidArgument,
            "Transfer.Asset.object field missing",
        )
    })?;
    let destination_value = asset_fields.remove("destination").ok_or_else(|| {
        CodecError::new(
            CodecErrorKind::InvalidArgument,
            "Transfer.Asset.destination field missing",
        )
    })?;
    let source: AssetId = json::from_value(source_value).map_err(codec_error)?;
    let quantity: Quantity = json::from_value(quantity_value).map_err(codec_error)?;
    let destination = parse_account_id_value(destination_value, "Transfer.Asset.destination")?;
    let transfer = Transfer::asset_quantity(source, quantity, destination);
    Ok(InstructionBox::from(TransferBox::Asset(transfer)))
}

/// Admit the strict `Transfer.Domain` payload.
fn transfer_domain_from_json(mut domain_fields: json::Map) -> CodecResult<InstructionBox> {
    let source_value = domain_fields.remove("source").ok_or_else(|| {
        CodecError::new(
            CodecErrorKind::InvalidArgument,
            "Transfer.Domain.source field missing",
        )
    })?;
    let object_value = domain_fields.remove("object").ok_or_else(|| {
        CodecError::new(
            CodecErrorKind::InvalidArgument,
            "Transfer.Domain.object field missing",
        )
    })?;
    let destination_value = domain_fields.remove("destination").ok_or_else(|| {
        CodecError::new(
            CodecErrorKind::InvalidArgument,
            "Transfer.Domain.destination field missing",
        )
    })?;
    let source = parse_account_id_value(source_value, "Transfer.Domain.source")?;
    let domain_id: DomainId = json::from_value(object_value).map_err(codec_error)?;
    let destination = parse_account_id_value(destination_value, "Transfer.Domain.destination")?;
    let transfer = Transfer::domain(source, domain_id, destination);
    Ok(InstructionBox::from(TransferBox::Domain(transfer)))
}

/// Admit the strict `Transfer.AssetDefinition` payload.
fn transfer_asset_definition_from_json(
    mut definition_fields: json::Map,
) -> CodecResult<InstructionBox> {
    let source_value = definition_fields.remove("source").ok_or_else(|| {
        CodecError::new(
            CodecErrorKind::InvalidArgument,
            "Transfer.AssetDefinition.source field missing",
        )
    })?;
    let object_value = definition_fields.remove("object").ok_or_else(|| {
        CodecError::new(
            CodecErrorKind::InvalidArgument,
            "Transfer.AssetDefinition.object field missing",
        )
    })?;
    let destination_value = definition_fields.remove("destination").ok_or_else(|| {
        CodecError::new(
            CodecErrorKind::InvalidArgument,
            "Transfer.AssetDefinition.destination field missing",
        )
    })?;
    let source = parse_account_id_value(source_value, "Transfer.AssetDefinition.source")?;
    let definition: AssetDefinitionId = json::from_value(object_value).map_err(codec_error)?;
    let destination =
        parse_account_id_value(destination_value, "Transfer.AssetDefinition.destination")?;
    let transfer = Transfer::asset_definition(source, definition, destination);
    Ok(InstructionBox::from(TransferBox::AssetDefinition(transfer)))
}

/// Admit the strict `Transfer.Nft` payload.
fn transfer_nft_from_json(mut nft_fields: json::Map) -> CodecResult<InstructionBox> {
    let source_value = nft_fields.remove("source").ok_or_else(|| {
        CodecError::new(
            CodecErrorKind::InvalidArgument,
            "Transfer.Nft.source field missing",
        )
    })?;
    let object_value = nft_fields.remove("object").ok_or_else(|| {
        CodecError::new(
            CodecErrorKind::InvalidArgument,
            "Transfer.Nft.object field missing",
        )
    })?;
    let destination_value = nft_fields.remove("destination").ok_or_else(|| {
        CodecError::new(
            CodecErrorKind::InvalidArgument,
            "Transfer.Nft.destination field missing",
        )
    })?;
    let source = parse_account_id_value(source_value, "Transfer.Nft.source")?;
    let nft_id: NftId = json::from_value(object_value).map_err(codec_error)?;
    let destination = parse_account_id_value(destination_value, "Transfer.Nft.destination")?;
    let transfer = Transfer::nft(source, nft_id, destination);
    Ok(InstructionBox::from(TransferBox::Nft(transfer)))
}

/// Admit the strict `Grant` instruction payload.
fn grant_from_json(mut grant_map: json::Map) -> CodecResult<InstructionBox> {
    if let Some(json::Value::Object(mut fields)) = grant_map.remove("Permission") {
        let object_value = required_value(&mut fields, "object", "Grant.Permission")?;
        let destination = parse_account_id_value(
            required_value(&mut fields, "destination", "Grant.Permission")?,
            "Grant.Permission.destination",
        )?;
        if !fields.is_empty() {
            return Err(CodecError::new(
                CodecErrorKind::InvalidArgument,
                format!(
                    "Grant.Permission contains unsupported fields: {}",
                    fields.keys().cloned().collect::<Vec<_>>().join(",")
                ),
            ));
        }
        let mut permission_fields = match object_value {
            json::Value::Object(map) => map,
            other => {
                return Err(CodecError::new(
                    CodecErrorKind::InvalidArgument,
                    format!("Grant.Permission.object must be an object (found {other:?})"),
                ));
            }
        };
        permission_fields
            .entry("payload".to_owned())
            .or_insert(json::Value::Null);
        let permission: Permission =
            json::from_value(json::Value::Object(permission_fields)).map_err(codec_error)?;
        let grant = Grant::account_permission(permission, destination);
        return Ok(InstructionBox::from(GrantBox::Permission(grant)));
    }
    Err(CodecError::new(
        CodecErrorKind::InvalidArgument,
        "unsupported Grant instruction variant; expected key: Permission",
    ))
}

/// Admit the strict `SetAssetDefinitionAlias` instruction payload.
fn set_asset_definition_alias_from_json(mut fields: json::Map) -> CodecResult<InstructionBox> {
    let asset_definition_id: AssetDefinitionId = parse_string_value(
        required_value(
            &mut fields,
            "asset_definition_id",
            "SetAssetDefinitionAlias",
        )?,
        "SetAssetDefinitionAlias.asset_definition_id",
    )?
    .parse()
    .map_err(|err| {
        CodecError::new(
            CodecErrorKind::InvalidArgument,
            format!("invalid SetAssetDefinitionAlias.asset_definition_id literal: {err}"),
        )
    })?;
    let alias =
        parse_optional_string_value(fields.remove("alias"), "SetAssetDefinitionAlias.alias")?
            .map(|literal| {
                literal.parse::<AssetDefinitionAlias>().map_err(|err| {
                    CodecError::new(
                        CodecErrorKind::InvalidArgument,
                        format!("invalid SetAssetDefinitionAlias.alias literal: {err}"),
                    )
                })
            })
            .transpose()?;
    let lease_expiry_ms = match fields.remove("lease_expiry_ms") {
        None | Some(json::Value::Null) => None,
        Some(value) => Some(parse_u64_value(
            value,
            "SetAssetDefinitionAlias.lease_expiry_ms",
        )?),
    };
    if !fields.is_empty() {
        return Err(CodecError::new(
            CodecErrorKind::InvalidArgument,
            format!(
                "SetAssetDefinitionAlias contains unsupported fields: {}",
                fields.keys().cloned().collect::<Vec<_>>().join(",")
            ),
        ));
    }
    let instruction = match alias {
        Some(alias) => SetAssetDefinitionAlias::bind(asset_definition_id, alias, lease_expiry_ms),
        None => SetAssetDefinitionAlias::clear(asset_definition_id),
    };
    Ok(InstructionBox::from(instruction))
}

/// Admit the strict `RegisterRwa` instruction payload.
fn register_rwa_from_json(mut fields: json::Map) -> CodecResult<InstructionBox> {
    let rwa_value = required_value(&mut fields, "rwa", "RegisterRwa")?;
    let json::Value::Object(mut fields) = rwa_value else {
        return Err(CodecError::new(
            CodecErrorKind::InvalidArgument,
            "RegisterRwa.rwa must be an object",
        ));
    };
    let domain: DomainId =
        json::from_value(required_value(&mut fields, "domain", "RegisterRwa.rwa")?)
            .map_err(codec_error)?;
    let quantity: Quantity =
        json::from_value(required_value(&mut fields, "quantity", "RegisterRwa.rwa")?)
            .map_err(codec_error)?;
    let spec = json::from_value(required_value(&mut fields, "spec", "RegisterRwa.rwa")?)
        .map_err(codec_error)?;
    let primary_reference = parse_string_value(
        required_value(&mut fields, "primary_reference", "RegisterRwa.rwa")?,
        "RegisterRwa.rwa.primary_reference",
    )?;
    let status: Option<Name> = fields
        .remove("status")
        .map_or(Ok(None), |value| match value {
            json::Value::Null => Ok(None),
            other => json::from_value(other).map_err(codec_error),
        })?;
    let metadata = fields
        .remove("metadata")
        .map_or(Ok(Metadata::default()), |value| {
            json::from_value(value).map_err(codec_error)
        })?;
    let parents = fields.remove("parents").map_or(Ok(Vec::new()), |value| {
        parse_rwa_parent_refs_value(value, "RegisterRwa.rwa.parents")
    })?;
    let controls = fields
        .remove("controls")
        .map_or(Ok(RwaControlPolicy::default()), |value| {
            json::from_value(value).map_err(codec_error)
        })?;
    let register = RegisterRwa {
        rwa: NewRwa::new(
            domain,
            quantity,
            spec,
            primary_reference,
            status,
            metadata,
            parents,
            controls,
        ),
    };
    Ok(InstructionBox::from(RwaInstructionBox::from(register)))
}

/// Admit the strict `TransferRwa` instruction payload.
fn transfer_rwa_from_json(mut fields: json::Map) -> CodecResult<InstructionBox> {
    let source = parse_account_id_value(
        required_value(&mut fields, "source", "TransferRwa")?,
        "TransferRwa.source",
    )?;
    let rwa = parse_rwa_id_value(
        required_value(&mut fields, "rwa", "TransferRwa")?,
        "TransferRwa.rwa",
    )?;
    let quantity: Quantity =
        json::from_value(required_value(&mut fields, "quantity", "TransferRwa")?)
            .map_err(codec_error)?;
    let destination = parse_account_id_value(
        required_value(&mut fields, "destination", "TransferRwa")?,
        "TransferRwa.destination",
    )?;
    Ok(InstructionBox::from(RwaInstructionBox::from(TransferRwa {
        source,
        rwa,
        quantity,
        destination,
    })))
}

/// Admit the strict `MergeRwas` instruction payload.
fn merge_rwas_from_json(mut fields: json::Map) -> CodecResult<InstructionBox> {
    let parents = parse_rwa_parent_refs_value(
        required_value(&mut fields, "parents", "MergeRwas")?,
        "MergeRwas.parents",
    )?;
    let primary_reference = parse_string_value(
        required_value(&mut fields, "primary_reference", "MergeRwas")?,
        "MergeRwas.primary_reference",
    )?;
    let status: Option<Name> = fields
        .remove("status")
        .map_or(Ok(None), |value| match value {
            json::Value::Null => Ok(None),
            other => json::from_value(other).map_err(codec_error),
        })?;
    let metadata = fields
        .remove("metadata")
        .map_or(Ok(Metadata::default()), |value| {
            json::from_value(value).map_err(codec_error)
        })?;
    Ok(InstructionBox::from(RwaInstructionBox::from(MergeRwas {
        parents,
        primary_reference,
        status,
        metadata,
    })))
}

/// Admit the strict `RedeemRwa` instruction payload.
fn redeem_rwa_from_json(mut fields: json::Map) -> CodecResult<InstructionBox> {
    let rwa = parse_rwa_id_value(
        required_value(&mut fields, "rwa", "RedeemRwa")?,
        "RedeemRwa.rwa",
    )?;
    let quantity: Quantity =
        json::from_value(required_value(&mut fields, "quantity", "RedeemRwa")?)
            .map_err(codec_error)?;
    Ok(InstructionBox::from(RwaInstructionBox::from(RedeemRwa {
        rwa,
        quantity,
    })))
}

/// Admit the strict `FreezeRwa` instruction payload.
fn freeze_rwa_from_json(mut fields: json::Map) -> CodecResult<InstructionBox> {
    let rwa = parse_rwa_id_value(
        required_value(&mut fields, "rwa", "FreezeRwa")?,
        "FreezeRwa.rwa",
    )?;
    Ok(InstructionBox::from(RwaInstructionBox::from(FreezeRwa {
        rwa,
    })))
}

/// Admit the strict `UnfreezeRwa` instruction payload.
fn unfreeze_rwa_from_json(mut fields: json::Map) -> CodecResult<InstructionBox> {
    let rwa = parse_rwa_id_value(
        required_value(&mut fields, "rwa", "UnfreezeRwa")?,
        "UnfreezeRwa.rwa",
    )?;
    Ok(InstructionBox::from(RwaInstructionBox::from(UnfreezeRwa {
        rwa,
    })))
}

/// Admit the strict `HoldRwa` instruction payload.
fn hold_rwa_from_json(mut fields: json::Map) -> CodecResult<InstructionBox> {
    let rwa = parse_rwa_id_value(
        required_value(&mut fields, "rwa", "HoldRwa")?,
        "HoldRwa.rwa",
    )?;
    let quantity: Quantity = json::from_value(required_value(&mut fields, "quantity", "HoldRwa")?)
        .map_err(codec_error)?;
    Ok(InstructionBox::from(RwaInstructionBox::from(HoldRwa {
        rwa,
        quantity,
    })))
}

/// Admit the strict `ReleaseRwa` instruction payload.
fn release_rwa_from_json(mut fields: json::Map) -> CodecResult<InstructionBox> {
    let rwa = parse_rwa_id_value(
        required_value(&mut fields, "rwa", "ReleaseRwa")?,
        "ReleaseRwa.rwa",
    )?;
    let quantity: Quantity =
        json::from_value(required_value(&mut fields, "quantity", "ReleaseRwa")?)
            .map_err(codec_error)?;
    Ok(InstructionBox::from(RwaInstructionBox::from(ReleaseRwa {
        rwa,
        quantity,
    })))
}

/// Admit the strict `ForceTransferRwa` instruction payload.
fn force_transfer_rwa_from_json(mut fields: json::Map) -> CodecResult<InstructionBox> {
    let rwa = parse_rwa_id_value(
        required_value(&mut fields, "rwa", "ForceTransferRwa")?,
        "ForceTransferRwa.rwa",
    )?;
    let quantity: Quantity =
        json::from_value(required_value(&mut fields, "quantity", "ForceTransferRwa")?)
            .map_err(codec_error)?;
    let destination = parse_account_id_value(
        required_value(&mut fields, "destination", "ForceTransferRwa")?,
        "ForceTransferRwa.destination",
    )?;
    Ok(InstructionBox::from(RwaInstructionBox::from(
        ForceTransferRwa {
            rwa,
            quantity,
            destination,
        },
    )))
}

/// Admit the strict `SetRwaControls` instruction payload.
fn set_rwa_controls_from_json(mut fields: json::Map) -> CodecResult<InstructionBox> {
    let rwa = parse_rwa_id_value(
        required_value(&mut fields, "rwa", "SetRwaControls")?,
        "SetRwaControls.rwa",
    )?;
    let controls: RwaControlPolicy =
        json::from_value(required_value(&mut fields, "controls", "SetRwaControls")?)
            .map_err(codec_error)?;
    Ok(InstructionBox::from(RwaInstructionBox::from(
        SetRwaControls { rwa, controls },
    )))
}

/// Admit the strict `SetRwaKeyValue` instruction payload.
fn set_rwa_key_value_from_json(mut fields: json::Map) -> CodecResult<InstructionBox> {
    let rwa = parse_rwa_id_value(
        required_value(&mut fields, "rwa", "SetRwaKeyValue")?,
        "SetRwaKeyValue.rwa",
    )?;
    let key: Name = json::from_value(required_value(&mut fields, "key", "SetRwaKeyValue")?)
        .map_err(codec_error)?;
    let value: Json = json::from_value(required_value(&mut fields, "value", "SetRwaKeyValue")?)
        .map_err(codec_error)?;
    Ok(InstructionBox::from(RwaInstructionBox::from(
        SetKeyValue::rwa(rwa, key, value),
    )))
}

/// Admit the strict `SetKeyValue` instruction payload.
fn set_key_value_from_json(mut variants: json::Map) -> CodecResult<InstructionBox> {
    if let Some(json::Value::Object(mut fields)) = variants.remove("Account") {
        let account = parse_account_id_value(
            required_value(&mut fields, "object", "SetKeyValue.Account")?,
            "SetKeyValue.Account.object",
        )?;
        let key: Name =
            json::from_value(required_value(&mut fields, "key", "SetKeyValue.Account")?)
                .map_err(codec_error)?;
        let value: Json =
            json::from_value(required_value(&mut fields, "value", "SetKeyValue.Account")?)
                .map_err(codec_error)?;
        if !fields.is_empty() {
            return Err(CodecError::new(
                CodecErrorKind::InvalidArgument,
                format!(
                    "SetKeyValue.Account contains unsupported fields: {}",
                    fields.keys().cloned().collect::<Vec<_>>().join(", ")
                ),
            ));
        }
        if !variants.is_empty() {
            return Err(CodecError::new(
                CodecErrorKind::InvalidArgument,
                "SetKeyValue must contain exactly one variant",
            ));
        }
        return Ok(InstructionBox::from(SetKeyValue::account(
            account, key, value,
        )));
    }
    if let Some(json::Value::Object(mut fields)) = variants.remove("Nft") {
        let nft_id: NftId =
            json::from_value(required_value(&mut fields, "object", "SetKeyValue.Nft")?)
                .map_err(codec_error)?;
        let key: Name = json::from_value(required_value(&mut fields, "key", "SetKeyValue.Nft")?)
            .map_err(codec_error)?;
        let value: Json =
            json::from_value(required_value(&mut fields, "value", "SetKeyValue.Nft")?)
                .map_err(codec_error)?;
        if !fields.is_empty() {
            return Err(CodecError::new(
                CodecErrorKind::InvalidArgument,
                format!(
                    "SetKeyValue.Nft contains unsupported fields: {}",
                    fields.keys().cloned().collect::<Vec<_>>().join(", ")
                ),
            ));
        }
        if !variants.is_empty() {
            return Err(CodecError::new(
                CodecErrorKind::InvalidArgument,
                "SetKeyValue must contain exactly one variant",
            ));
        }
        return Ok(InstructionBox::from(SetKeyValue::nft(nft_id, key, value)));
    }
    Err(CodecError::new(
        CodecErrorKind::InvalidArgument,
        "SetKeyValue currently supports the Account and Nft variants",
    ))
}

/// Admit the strict `RemoveRwaKeyValue` instruction payload.
fn remove_rwa_key_value_from_json(mut fields: json::Map) -> CodecResult<InstructionBox> {
    let rwa = parse_rwa_id_value(
        required_value(&mut fields, "rwa", "RemoveRwaKeyValue")?,
        "RemoveRwaKeyValue.rwa",
    )?;
    let key: Name = json::from_value(required_value(&mut fields, "key", "RemoveRwaKeyValue")?)
        .map_err(codec_error)?;
    Ok(InstructionBox::from(RwaInstructionBox::from(
        RemoveKeyValue::rwa(rwa, key),
    )))
}

/// Admit the strict `Kaigi` instruction payload.
fn kaigi_from_json(mut kaigi_map: json::Map) -> CodecResult<InstructionBox> {
    if let Some(json::Value::Object(create_fields)) = kaigi_map.remove("CreateKaigi") {
        return create_kaigi_from_json(create_fields);
    }
    if let Some(json::Value::Object(join_fields)) = kaigi_map.remove("JoinKaigi") {
        return join_kaigi_from_json(join_fields);
    }
    if let Some(json::Value::Object(leave_fields)) = kaigi_map.remove("LeaveKaigi") {
        return leave_kaigi_from_json(leave_fields);
    }
    if let Some(json::Value::Object(end_fields)) = kaigi_map.remove("EndKaigi") {
        return end_kaigi_from_json(end_fields);
    }
    if let Some(json::Value::Object(usage_fields)) = kaigi_map.remove("RecordKaigiUsage") {
        return record_kaigi_usage_from_json(usage_fields);
    }
    if let Some(json::Value::Object(manifest_fields)) = kaigi_map.remove("SetKaigiRelayManifest") {
        return set_kaigi_relay_manifest_from_json(manifest_fields);
    }
    if let Some(json::Value::Object(register_fields)) = kaigi_map.remove("RegisterKaigiRelay") {
        return register_kaigi_relay_from_json(register_fields);
    }
    if let Some(json::Value::Object(unregister_fields)) = kaigi_map.remove("UnregisterKaigiRelay") {
        return unregister_kaigi_relay_from_json(unregister_fields);
    }
    if let Some(json::Value::Object(health_fields)) = kaigi_map.remove("ReportKaigiRelayHealth") {
        return report_kaigi_relay_health_from_json(health_fields);
    }
    Err(CodecError::new(
        CodecErrorKind::InvalidArgument,
        "unsupported Kaigi instruction variant; see iroha_data_model::isi::kaigi for supported set",
    ))
}

/// Admit the strict `Kaigi.CreateKaigi` payload.
fn create_kaigi_from_json(mut create_fields: json::Map) -> CodecResult<InstructionBox> {
    let call_value = create_fields.remove("call").ok_or_else(|| {
        CodecError::new(
            CodecErrorKind::InvalidArgument,
            "CreateKaigi.call field missing",
        )
    })?;
    let call = kaigi::parse_call(call_value)?;
    let commitment = parse_optional_commitment(create_fields.remove("commitment"), "CreateKaigi")?;
    let nullifier = parse_optional_nullifier(create_fields.remove("nullifier"), "CreateKaigi")?;
    let roster_root = parse_optional_hash(
        create_fields.remove("roster_root"),
        "CreateKaigi.roster_root",
    )?;
    let proof = parse_optional_base64(create_fields.remove("proof"), "CreateKaigi.proof")?;
    let instruction = CreateKaigi {
        call,
        commitment,
        nullifier,
        roster_root,
        proof,
    };
    Ok(Box::new(instruction).into_instruction_box())
}

/// Admit the strict `Kaigi.JoinKaigi` payload.
fn join_kaigi_from_json(mut join_fields: json::Map) -> CodecResult<InstructionBox> {
    let call_id_value = join_fields.remove("call_id").ok_or_else(|| {
        CodecError::new(
            CodecErrorKind::InvalidArgument,
            "JoinKaigi.call_id field missing",
        )
    })?;
    let call_id: KaigiId = json::from_value(call_id_value).map_err(codec_error)?;
    let participant_value = join_fields.remove("participant").ok_or_else(|| {
        CodecError::new(
            CodecErrorKind::InvalidArgument,
            "JoinKaigi.participant field missing",
        )
    })?;
    let participant = parse_account_id_value(participant_value, "JoinKaigi.participant")?;
    let commitment = parse_optional_commitment(join_fields.remove("commitment"), "JoinKaigi")?;
    let nullifier = parse_optional_nullifier(join_fields.remove("nullifier"), "JoinKaigi")?;
    let roster_root =
        parse_optional_hash(join_fields.remove("roster_root"), "JoinKaigi.roster_root")?;
    let proof = parse_optional_base64(join_fields.remove("proof"), "JoinKaigi.proof")?;
    let join = JoinKaigi {
        call_id,
        participant,
        commitment,
        nullifier,
        roster_root,
        proof,
    };
    Ok(Box::new(join).into_instruction_box())
}

/// Admit the strict `Kaigi.LeaveKaigi` payload.
fn leave_kaigi_from_json(mut leave_fields: json::Map) -> CodecResult<InstructionBox> {
    let call_id_value = leave_fields.remove("call_id").ok_or_else(|| {
        CodecError::new(
            CodecErrorKind::InvalidArgument,
            "LeaveKaigi.call_id field missing",
        )
    })?;
    let call_id: KaigiId = json::from_value(call_id_value).map_err(codec_error)?;
    let participant_value = leave_fields.remove("participant").ok_or_else(|| {
        CodecError::new(
            CodecErrorKind::InvalidArgument,
            "LeaveKaigi.participant field missing",
        )
    })?;
    let participant = parse_account_id_value(participant_value, "LeaveKaigi.participant")?;
    let commitment = parse_optional_commitment(leave_fields.remove("commitment"), "LeaveKaigi")?;
    let nullifier = parse_optional_nullifier(leave_fields.remove("nullifier"), "LeaveKaigi")?;
    let roster_root =
        parse_optional_hash(leave_fields.remove("roster_root"), "LeaveKaigi.roster_root")?;
    let proof = parse_optional_base64(leave_fields.remove("proof"), "LeaveKaigi.proof")?;
    let leave = LeaveKaigi {
        call_id,
        participant,
        commitment,
        nullifier,
        roster_root,
        proof,
    };
    Ok(Box::new(leave).into_instruction_box())
}

/// Admit the strict `Kaigi.EndKaigi` payload.
fn end_kaigi_from_json(mut end_fields: json::Map) -> CodecResult<InstructionBox> {
    let call_id_value = end_fields.remove("call_id").ok_or_else(|| {
        CodecError::new(
            CodecErrorKind::InvalidArgument,
            "EndKaigi.call_id field missing",
        )
    })?;
    let call_id: KaigiId = json::from_value(call_id_value).map_err(codec_error)?;
    let ended_at = match end_fields.remove("ended_at_ms") {
        None | Some(json::Value::Null) => None,
        Some(value) => Some(kaigi::parse_u64(value, "EndKaigi.ended_at_ms")?),
    };
    let commitment = parse_optional_commitment(end_fields.remove("commitment"), "EndKaigi")?;
    let nullifier = parse_optional_nullifier(end_fields.remove("nullifier"), "EndKaigi")?;
    let roster_root =
        parse_optional_hash(end_fields.remove("roster_root"), "EndKaigi.roster_root")?;
    let proof = parse_optional_base64(end_fields.remove("proof"), "EndKaigi.proof")?;
    let end = EndKaigi {
        call_id,
        ended_at_ms: ended_at,
        commitment,
        nullifier,
        roster_root,
        proof,
    };
    Ok(Box::new(end).into_instruction_box())
}

/// Admit the strict `Kaigi.RecordKaigiUsage` payload.
fn record_kaigi_usage_from_json(mut usage_fields: json::Map) -> CodecResult<InstructionBox> {
    let call_id_value = usage_fields.remove("call_id").ok_or_else(|| {
        CodecError::new(
            CodecErrorKind::InvalidArgument,
            "RecordKaigiUsage.call_id field missing",
        )
    })?;
    let call_id: KaigiId = json::from_value(call_id_value).map_err(codec_error)?;
    let duration_value = usage_fields.remove("duration_ms").ok_or_else(|| {
        CodecError::new(
            CodecErrorKind::InvalidArgument,
            "RecordKaigiUsage.duration_ms field missing",
        )
    })?;
    let duration_ms = kaigi::parse_u64(duration_value, "RecordKaigiUsage.duration_ms")?;
    let billed_gas = usage_fields
        .remove("billed_gas")
        .map(|value| kaigi::parse_u64(value, "RecordKaigiUsage.billed_gas"))
        .transpose()?
        .unwrap_or_default();
    let usage_commitment = parse_optional_kaigi_scalar(
        usage_fields.remove("usage_commitment"),
        "RecordKaigiUsage.usage_commitment",
    )?;
    let proof = parse_optional_base64(usage_fields.remove("proof"), "RecordKaigiUsage.proof")?;
    let usage = RecordKaigiUsage {
        call_id,
        duration_ms,
        billed_gas,
        usage_commitment,
        proof,
    };
    Ok(Box::new(usage).into_instruction_box())
}

/// Admit the strict `Kaigi.SetKaigiRelayManifest` payload.
fn set_kaigi_relay_manifest_from_json(
    mut manifest_fields: json::Map,
) -> CodecResult<InstructionBox> {
    let call_id_value = manifest_fields.remove("call_id").ok_or_else(|| {
        CodecError::new(
            CodecErrorKind::InvalidArgument,
            "SetKaigiRelayManifest.call_id field missing",
        )
    })?;
    let call_id: KaigiId = json::from_value(call_id_value).map_err(codec_error)?;
    let relay_manifest = manifest_fields
        .remove("relay_manifest")
        .map_or(Ok(None), |value| match value {
            json::Value::Null => Ok(None),
            other => kaigi::parse_relay_manifest(other).map(Some),
        })?;
    let manifest = SetKaigiRelayManifest {
        call_id,
        relay_manifest,
    };
    Ok(Box::new(manifest).into_instruction_box())
}

/// Admit the strict `Kaigi.RegisterKaigiRelay` payload.
fn register_kaigi_relay_from_json(mut register_fields: json::Map) -> CodecResult<InstructionBox> {
    let relay_value = register_fields.remove("relay").ok_or_else(|| {
        CodecError::new(
            CodecErrorKind::InvalidArgument,
            "RegisterKaigiRelay.relay field missing",
        )
    })?;
    let relay: KaigiRelayRegistration = json::from_value(relay_value).map_err(codec_error)?;
    let registration = RegisterKaigiRelay { relay };
    Ok(Box::new(registration).into_instruction_box())
}

/// Admit the strict `Kaigi.UnregisterKaigiRelay` payload.
fn unregister_kaigi_relay_from_json(
    mut unregister_fields: json::Map,
) -> CodecResult<InstructionBox> {
    let relay_id_value = unregister_fields.remove("relay_id").ok_or_else(|| {
        CodecError::new(
            CodecErrorKind::InvalidArgument,
            "UnregisterKaigiRelay.relay_id field missing",
        )
    })?;
    let relay_id = parse_account_id_value(relay_id_value, "UnregisterKaigiRelay.relay_id")?;
    Ok(Box::new(UnregisterKaigiRelay { relay_id }).into_instruction_box())
}

/// Admit the strict `Kaigi.ReportKaigiRelayHealth` payload.
fn report_kaigi_relay_health_from_json(
    mut health_fields: json::Map,
) -> CodecResult<InstructionBox> {
    let call_id_value = health_fields.remove("call_id").ok_or_else(|| {
        CodecError::new(
            CodecErrorKind::InvalidArgument,
            "ReportKaigiRelayHealth.call_id field missing",
        )
    })?;
    let call_id: KaigiId = json::from_value(call_id_value).map_err(codec_error)?;
    let relay_id_value = health_fields.remove("relay_id").ok_or_else(|| {
        CodecError::new(
            CodecErrorKind::InvalidArgument,
            "ReportKaigiRelayHealth.relay_id field missing",
        )
    })?;
    let relay_id = parse_account_id_value(relay_id_value, "ReportKaigiRelayHealth.relay_id")?;
    let status_value = health_fields.remove("status").ok_or_else(|| {
        CodecError::new(
            CodecErrorKind::InvalidArgument,
            "ReportKaigiRelayHealth.status field missing",
        )
    })?;
    let status: KaigiRelayHealthStatus = json::from_value(status_value).map_err(codec_error)?;
    let reported_at_ms = health_fields
        .remove("reported_at_ms")
        .map_or(Ok(0_u64), |value| {
            kaigi::parse_u64(value, "ReportKaigiRelayHealth.reported_at_ms")
        })?;
    let notes = health_fields
        .remove("notes")
        .map_or(Ok(None), |value| match value {
            json::Value::Null => Ok(None),
            other => json::from_value(other).map(Some).map_err(codec_error),
        })?;
    let report = ReportKaigiRelayHealth {
        call_id,
        relay_id,
        status,
        reported_at_ms,
        notes,
    };
    Ok(Box::new(report).into_instruction_box())
}

/// Admit the strict `ProposeDeployContract` instruction payload.
fn propose_deploy_contract_from_json(mut fields: json::Map) -> CodecResult<InstructionBox> {
    let contract_address: iroha_data_model::smart_contract::ContractAddress = parse_string_value(
        required_value(&mut fields, "contract_address", "ProposeDeployContract")?,
        "ProposeDeployContract.contract_address",
    )?
    .parse()
    .map_err(|err| {
        CodecError::new(
            CodecErrorKind::InvalidArgument,
            format!("invalid ProposeDeployContract.contract_address literal: {err}"),
        )
    })?;
    let code_hash: ContractCodeHash = json::from_value(required_value(
        &mut fields,
        "code_hash",
        "ProposeDeployContract",
    )?)
    .map_err(codec_error)?;
    let abi_hash: ContractAbiHash = json::from_value(required_value(
        &mut fields,
        "abi_hash",
        "ProposeDeployContract",
    )?)
    .map_err(codec_error)?;
    let abi_version: AbiVersion = json::from_value(required_value(
        &mut fields,
        "abi_version",
        "ProposeDeployContract",
    )?)
    .map_err(codec_error)?;
    let manifest_provenance = match fields.remove("manifest_provenance") {
        None | Some(json::Value::Null) => None,
        Some(value) => Some(json::from_value(value).map_err(codec_error)?),
    };
    if !fields.is_empty() {
        return Err(CodecError::new(
            CodecErrorKind::InvalidArgument,
            format!(
                "ProposeDeployContract contains unexpected field(s): {}",
                fields.keys().cloned().collect::<Vec<_>>().join(", ")
            ),
        ));
    }
    let instruction = ProposeDeployContract {
        contract_address,
        code_hash,
        abi_hash,
        abi_version,
        manifest_provenance,
    };
    Ok(Box::new(instruction).into_instruction_box())
}

/// Admit the strict `CastZkBallot` instruction payload.
fn cast_zk_ballot_from_json(mut fields: json::Map) -> CodecResult<InstructionBox> {
    let election_id = parse_string_value(
        required_value(&mut fields, "election_id", "CastZkBallot")?,
        "CastZkBallot.election_id",
    )?;
    let proof_b64 = parse_string_value(
        required_value(&mut fields, "proof_b64", "CastZkBallot")?,
        "CastZkBallot.proof_b64",
    )?;
    let public_inputs_json = parse_string_value(
        required_value(&mut fields, "public_inputs_json", "CastZkBallot")?,
        "CastZkBallot.public_inputs_json",
    )?;
    let public_inputs_json = normalize_zk_ballot_public_inputs_json(
        public_inputs_json.as_str(),
        "CastZkBallot.public_inputs_json",
    )?;
    let ballot = CastZkBallot {
        election_id,
        proof_b64,
        public_inputs_json,
    };
    Ok(Box::new(ballot).into_instruction_box())
}

/// Admit the strict `RegisterCitizen` instruction payload.
fn register_citizen_from_json(mut fields: json::Map) -> CodecResult<InstructionBox> {
    let owner_value = required_value(&mut fields, "owner", "RegisterCitizen")?;
    let owner = parse_account_id_value(owner_value, "RegisterCitizen.owner")?;
    let amount = parse_canonical_quantity_value(
        required_value(&mut fields, "amount", "RegisterCitizen")?,
        "RegisterCitizen.amount",
    )?;
    let instruction = RegisterCitizen { owner, amount };
    Ok(Box::new(instruction).into_instruction_box())
}

/// Admit the strict `SubmitAgendaProposal` instruction payload.
fn submit_agenda_proposal_from_json(mut fields: json::Map) -> CodecResult<InstructionBox> {
    let proposal: AgendaProposalV1 = json::from_value(required_value(
        &mut fields,
        "proposal",
        "SubmitAgendaProposal",
    )?)
    .map_err(codec_error)?;
    let instruction = SubmitAgendaProposal { proposal };
    Ok(Box::new(instruction).into_instruction_box())
}

/// Admit the strict `RegisterSmartContractCode` instruction payload.
fn register_smart_contract_code_from_json(
    envelope: &json::Map,
    mut fields: json::Map,
) -> CodecResult<InstructionBox> {
    require_exact_json_fields(envelope, &[], "RegisterSmartContractCode envelope")?;
    require_exact_json_fields(
        &fields,
        &["artifact_id", "manifest"],
        "RegisterSmartContractCode",
    )?;
    let artifact_id = lifecycle_instructions::parse_artifact_id(
        required_value(&mut fields, "artifact_id", "RegisterSmartContractCode")?,
        "RegisterSmartContractCode.artifact_id",
    )?;
    let manifest_value = required_value(&mut fields, "manifest", "RegisterSmartContractCode")?;
    let manifest: ContractManifest = json::from_value(manifest_value).map_err(codec_error)?;
    manifest::validate_manifest_schemas(&manifest)?;
    let instruction = RegisterSmartContractCode {
        artifact_id,
        manifest,
    };
    Ok(Box::new(instruction).into_instruction_box())
}

/// Admit the strict `RegisterSmartContractBytes` instruction payload.
fn register_smart_contract_bytes_from_json(
    envelope: &json::Map,
    mut fields: json::Map,
) -> CodecResult<InstructionBox> {
    require_exact_json_fields(envelope, &[], "RegisterSmartContractBytes envelope")?;
    require_exact_json_fields(
        &fields,
        &["artifact_id", "code"],
        "RegisterSmartContractBytes",
    )?;
    let artifact_id = lifecycle_instructions::parse_artifact_id(
        required_value(&mut fields, "artifact_id", "RegisterSmartContractBytes")?,
        "RegisterSmartContractBytes.artifact_id",
    )?;
    let code_value = required_value(&mut fields, "code", "RegisterSmartContractBytes")?;
    let code = parse_base64(code_value, "RegisterSmartContractBytes.code")?;
    let instruction = RegisterSmartContractBytes { artifact_id, code };
    Ok(Box::new(instruction).into_instruction_box())
}

/// Admit the strict `RemoveSmartContractBytes` instruction payload.
fn remove_smart_contract_bytes_from_json(
    envelope: &json::Map,
    mut fields: json::Map,
) -> CodecResult<InstructionBox> {
    require_exact_json_fields(envelope, &[], "RemoveSmartContractBytes envelope")?;
    let expected = if fields.contains_key("reason") {
        &["artifact_id", "reason"][..]
    } else {
        &["artifact_id"][..]
    };
    require_exact_json_fields(&fields, expected, "RemoveSmartContractBytes")?;
    let artifact_id = lifecycle_instructions::parse_artifact_id(
        required_value(&mut fields, "artifact_id", "RemoveSmartContractBytes")?,
        "RemoveSmartContractBytes.artifact_id",
    )?;
    let reason =
        parse_optional_string_value(fields.remove("reason"), "RemoveSmartContractBytes.reason")?;
    require_exact_json_fields(&fields, &[], "RemoveSmartContractBytes")?;
    let instruction = RemoveSmartContractBytes {
        artifact_id,
        reason,
    };
    Ok(Box::new(instruction).into_instruction_box())
}

/// Admit the strict `ClaimTwitterFollowReward` instruction payload.
fn claim_twitter_follow_reward_from_json(value: json::Value) -> CodecResult<InstructionBox> {
    let mut fields = match value {
        json::Value::Object(map) => map,
        other => {
            return Err(CodecError::new(
                CodecErrorKind::InvalidArgument,
                format!("ClaimTwitterFollowReward payload must be an object (found {other:?})"),
            ));
        }
    };
    let binding_hash = parse_keyed_hash(
        required_value(&mut fields, "binding_hash", "ClaimTwitterFollowReward")?,
        "ClaimTwitterFollowReward.binding_hash",
    )?;
    let instruction = ClaimTwitterFollowReward { binding_hash };
    Ok(Box::new(instruction).into_instruction_box())
}

/// Admit the strict `SendToTwitter` instruction payload.
fn send_to_twitter_from_json(value: json::Value) -> CodecResult<InstructionBox> {
    let mut fields = match value {
        json::Value::Object(map) => map,
        other => {
            return Err(CodecError::new(
                CodecErrorKind::InvalidArgument,
                format!("SendToTwitter payload must be an object (found {other:?})"),
            ));
        }
    };
    let binding_hash = parse_keyed_hash(
        required_value(&mut fields, "binding_hash", "SendToTwitter")?,
        "SendToTwitter.binding_hash",
    )?;
    let amount: Quantity =
        json::from_value(required_value(&mut fields, "amount", "SendToTwitter")?)
            .map_err(codec_error)?;
    let instruction = SendToTwitter {
        binding_hash,
        amount,
    };
    Ok(Box::new(instruction).into_instruction_box())
}

/// Admit the strict `CancelTwitterEscrow` instruction payload.
fn cancel_twitter_escrow_from_json(value: json::Value) -> CodecResult<InstructionBox> {
    let mut fields = match value {
        json::Value::Object(map) => map,
        other => {
            return Err(CodecError::new(
                CodecErrorKind::InvalidArgument,
                format!("CancelTwitterEscrow payload must be an object (found {other:?})"),
            ));
        }
    };
    let binding_hash = parse_keyed_hash(
        required_value(&mut fields, "binding_hash", "CancelTwitterEscrow")?,
        "CancelTwitterEscrow.binding_hash",
    )?;
    let instruction = CancelTwitterEscrow { binding_hash };
    Ok(Box::new(instruction).into_instruction_box())
}

/// Admit the strict `Custom` instruction payload.
fn custom_from_json(custom_value: json::Value) -> CodecResult<InstructionBox> {
    let mut custom_map = match custom_value {
        json::Value::Object(map) => map,
        other => {
            return Err(CodecError::new(
                CodecErrorKind::InvalidArgument,
                format!("Custom instruction payload must be an object (found {other:?})"),
            ));
        }
    };
    let payload = remove_case_insensitive(&mut custom_map, "payload").ok_or_else(|| {
        CodecError::new(
            CodecErrorKind::InvalidArgument,
            "Custom.payload field missing",
        )
    })?;
    Ok(InstructionBox::from(CustomInstruction::new(payload)))
}

/// Admit the strict `Multisig` instruction payload.
fn multisig_from_json(multisig_value: json::Value) -> CodecResult<InstructionBox> {
    let multisig_map = match multisig_value {
        json::Value::Object(map) => map,
        other => {
            return Err(CodecError::new(
                CodecErrorKind::InvalidArgument,
                format!("Multisig instruction payload must be an object (found {other:?})"),
            ));
        }
    };
    Ok(InstructionBox::from(CustomInstruction::new(
        json::Value::Object(multisig_map),
    )))
}

/// Admit the strict `MultisigPropose` instruction payload.
fn multisig_propose_from_json(propose_value: json::Value) -> CodecResult<InstructionBox> {
    let propose_fields = match propose_value {
        json::Value::Object(map) => map,
        other => {
            return Err(CodecError::new(
                CodecErrorKind::InvalidArgument,
                format!("MultisigPropose payload must be an object (found {other:?})"),
            ));
        }
    };
    let mut payload = json::Map::new();
    payload.insert("Propose".to_owned(), json::Value::Object(propose_fields));
    Ok(InstructionBox::from(CustomInstruction::new(
        json::Value::Object(payload),
    )))
}

/// Admit the strict `MultisigApprove` instruction payload.
fn multisig_approve_from_json(approve_value: json::Value) -> CodecResult<InstructionBox> {
    let approve_fields = match approve_value {
        json::Value::Object(map) => map,
        other => {
            return Err(CodecError::new(
                CodecErrorKind::InvalidArgument,
                format!("MultisigApprove payload must be an object (found {other:?})"),
            ));
        }
    };
    let mut payload = json::Map::new();
    payload.insert("Approve".to_owned(), json::Value::Object(approve_fields));
    Ok(InstructionBox::from(CustomInstruction::new(
        json::Value::Object(payload),
    )))
}

/// Admit the strict `MultisigCancel` instruction payload.
fn multisig_cancel_from_json(cancel_value: json::Value) -> CodecResult<InstructionBox> {
    let cancel_fields = match cancel_value {
        json::Value::Object(map) => map,
        other => {
            return Err(CodecError::new(
                CodecErrorKind::InvalidArgument,
                format!("MultisigCancel payload must be an object (found {other:?})"),
            ));
        }
    };
    let mut payload = json::Map::new();
    payload.insert("Cancel".to_owned(), json::Value::Object(cancel_fields));
    Ok(InstructionBox::from(CustomInstruction::new(
        json::Value::Object(payload),
    )))
}

/// Admit the strict `MultisigRegister` instruction payload.
fn multisig_register_from_json(register_value: json::Value) -> CodecResult<InstructionBox> {
    let register_fields = match register_value {
        json::Value::Object(map) => map,
        other => {
            return Err(CodecError::new(
                CodecErrorKind::InvalidArgument,
                format!("MultisigRegister payload must be an object (found {other:?})"),
            ));
        }
    };
    let mut payload = json::Map::new();
    payload.insert("Register".to_owned(), json::Value::Object(register_fields));
    Ok(InstructionBox::from(CustomInstruction::new(
        json::Value::Object(payload),
    )))
}

/// Admit the strict `Zk` instruction payload.
fn zk_from_json(zk_value: json::Value) -> CodecResult<InstructionBox> {
    let mut zk_map = match zk_value {
        json::Value::Object(map) => map,
        other => {
            return Err(CodecError::new(
                CodecErrorKind::InvalidArgument,
                format!("Zk instruction payload must be an object (found {other:?})"),
            ));
        }
    };
    if let Some(payload) = zk_map.remove("RegisterZkAsset") {
        let instruction: RegisterZkAsset = json::from_value(payload).map_err(codec_error)?;
        return Ok(Box::new(instruction).into_instruction_box());
    }
    if let Some(payload) = zk_map.remove("ScheduleConfidentialPolicyTransition") {
        let instruction: ScheduleConfidentialPolicyTransition =
            json::from_value(payload).map_err(codec_error)?;
        return Ok(Box::new(instruction).into_instruction_box());
    }
    if let Some(payload) = zk_map.remove("CancelConfidentialPolicyTransition") {
        let instruction: CancelConfidentialPolicyTransition =
            json::from_value(payload).map_err(codec_error)?;
        return Ok(Box::new(instruction).into_instruction_box());
    }
    if let Some(payload) = zk_map.remove("CreateElection") {
        let instruction: CreateElection = json::from_value(payload).map_err(codec_error)?;
        return Ok(Box::new(instruction).into_instruction_box());
    }
    if let Some(payload) = zk_map.remove("SubmitBallot") {
        let instruction: SubmitBallot = json::from_value(payload).map_err(codec_error)?;
        return Ok(Box::new(instruction).into_instruction_box());
    }
    if let Some(payload) = zk_map.remove("FinalizeElection") {
        let instruction: FinalizeElection = json::from_value(payload).map_err(codec_error)?;
        return Ok(Box::new(instruction).into_instruction_box());
    }
    Err(CodecError::new(
        CodecErrorKind::InvalidArgument,
        "unsupported zk instruction variant",
    ))
}

fn settlement_instruction_from_json(value: json::Value) -> CodecResult<InstructionBox> {
    let json::Value::Object(mut variants) = value else {
        return Err(CodecError::new(
            CodecErrorKind::InvalidArgument,
            "Settlement instruction must be an object containing exactly one variant",
        ));
    };
    if variants.len() != 1 {
        return Err(CodecError::new(
            CodecErrorKind::InvalidArgument,
            "Settlement instruction must contain exactly one supported settlement variant",
        ));
    }
    let (variant, payload) = variants
        .pop_first()
        .expect("length checked settlement variant");
    let instruction = match variant.as_str() {
        "Atomic" => atomic_settlement_from_json(payload)?,
        "Dvp" => {
            SettlementInstructionBox::Dvp(json::from_value::<DvpIsi>(payload).map_err(codec_error)?)
        }
        "Pvp" => {
            SettlementInstructionBox::Pvp(json::from_value::<PvpIsi>(payload).map_err(codec_error)?)
        }
        "SetFxCorridorPolicy" => {
            let set = json::from_value::<SetFxCorridorPolicy>(payload).map_err(codec_error)?;
            if let Some(error) = set.policy.invariant_error() {
                return Err(CodecError::new(CodecErrorKind::InvalidArgument, error));
            }
            SettlementInstructionBox::SetFxCorridorPolicy(set)
        }
        "FundFxCorridorEscrow" => {
            let fund = json::from_value::<FundFxCorridorEscrow>(payload).map_err(codec_error)?;
            if fund.amount.is_zero() {
                return Err(CodecError::new(
                    CodecErrorKind::InvalidArgument,
                    "FundFxCorridorEscrow.amount must be positive",
                ));
            }
            SettlementInstructionBox::FundFxCorridorEscrow(fund)
        }
        "RefundFxCorridorEscrow" => {
            let refund =
                json::from_value::<RefundFxCorridorEscrow>(payload).map_err(codec_error)?;
            if refund.amount.is_zero() {
                return Err(CodecError::new(
                    CodecErrorKind::InvalidArgument,
                    "RefundFxCorridorEscrow.amount must be positive",
                ));
            }
            SettlementInstructionBox::RefundFxCorridorEscrow(refund)
        }
        "SettleFxCorridor" => fx_corridor_settlement_from_json(payload)?,
        _ => {
            return Err(CodecError::new(
                CodecErrorKind::InvalidArgument,
                format!("unsupported Settlement instruction variant `{variant}`"),
            ));
        }
    };
    Ok(InstructionBox::from(instruction))
}

/// Admit an exact atomic settlement that satisfies its model invariants.
fn atomic_settlement_from_json(payload: json::Value) -> CodecResult<SettlementInstructionBox> {
    exact_json_object_fields(
        &payload,
        &[
            "network_id",
            "settlement_id",
            "movements",
            "expires_at_height",
            "metadata",
        ],
        "Atomic",
    )?;
    let atomic =
        json::from_value::<iroha_data_model::isi::SettleAtomic>(payload).map_err(codec_error)?;
    atomic
        .validate()
        .map_err(|reason| CodecError::new(CodecErrorKind::InvalidArgument, reason))?;
    Ok(SettlementInstructionBox::Atomic(atomic))
}

/// Admit an exact FX corridor settlement with a positive source amount.
fn fx_corridor_settlement_from_json(payload: json::Value) -> CodecResult<SettlementInstructionBox> {
    exact_json_object_fields(
        &payload,
        &[
            "policy_id",
            "expected_policy_revision",
            "source_asset_definition_id",
            "destination_asset_definition_id",
            "settlement_id",
            "recipient",
            "source_amount",
            "expected_destination_amount",
            "oracle_evidence",
        ],
        "SettleFxCorridor",
    )?;
    let settle = json::from_value::<SettleFxCorridor>(payload).map_err(codec_error)?;
    if settle.source_amount.is_zero() {
        return Err(CodecError::new(
            CodecErrorKind::InvalidArgument,
            "SettleFxCorridor.source_amount must be positive",
        ));
    }
    Ok(SettlementInstructionBox::SettleFxCorridor(settle))
}

fn exact_json_object_fields(
    value: &json::Value,
    expected: &[&str],
    context: &str,
) -> CodecResult<()> {
    let json::Value::Object(fields) = value else {
        return Err(CodecError::new(
            CodecErrorKind::InvalidArgument,
            format!("{context} payload must be an object"),
        ));
    };
    let unknown = fields
        .keys()
        .filter(|key| !expected.contains(&key.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if !unknown.is_empty() {
        return Err(CodecError::new(
            CodecErrorKind::InvalidArgument,
            format!(
                "{context} contains unexpected field(s): {}",
                unknown.join(", ")
            ),
        ));
    }
    let missing = expected
        .iter()
        .copied()
        .filter(|key| !fields.contains_key(*key))
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(CodecError::new(
            CodecErrorKind::InvalidArgument,
            format!("{context} is missing field(s): {}", missing.join(", ")),
        ));
    }
    Ok(())
}

/// Render a typed instruction through its canonical JavaScript JSON contract.
///
/// # Errors
///
/// Returns an error when the instruction has no strict JSON contract, when one of its
/// values cannot be serialized or rendered canonically, or when it violates an
/// invariant its JSON contract requires.
pub fn instruction_to_json_value(instruction: &InstructionBox) -> CodecResult<json::Value> {
    if let Some(value) = plain_governance::to_json(instruction) {
        return value;
    }
    if let Some(value) = retail_daily_limit_instructions::to_json(instruction) {
        return value;
    }
    if let Some(value) = staking_instructions::to_json(instruction) {
        return value;
    }
    if let Some(value) = activation_instructions::to_json(instruction) {
        return value;
    }
    if let Some(value) = lifecycle_instructions::to_json(instruction) {
        return value;
    }
    if let Some(value) = game_instructions::to_json(instruction) {
        return value;
    }
    if let Some(value) = verifying_key_instructions::to_json(instruction) {
        return value;
    }
    let instruction_ref: &dyn InstructionTrait = &**instruction;
    INSTRUCTION_RENDERERS
        .iter()
        .find_map(|render| render(instruction_ref))
        .unwrap_or_else(|| {
            Err(CodecError::new(
                CodecErrorKind::Failure,
                "unsupported instruction variant; JSON conversion is not yet implemented for this instruction",
            ))
        })
}

/// Renderer for one group of concrete instruction types.
type InstructionRenderer = fn(&dyn InstructionTrait) -> Option<CodecResult<json::Value>>;

/// Renderers for the instructions whose strict JSON contract lives in this module.
///
/// A renderer returns `None` unless the instruction is one of its concrete types
/// (or, for partially covered boxes, one of the covered variants).
const INSTRUCTION_RENDERERS: [InstructionRenderer; 5] = [
    asset_instruction_to_json,
    ledger_instruction_to_json,
    rwa_instruction_to_json,
    governance_instruction_to_json,
    kaigi_instruction_to_json,
];

/// Render `instruction` with `render` when it is a `T`.
fn render_as<T: 'static>(
    instruction: &dyn InstructionTrait,
    render: fn(&T) -> CodecResult<json::Value>,
) -> Option<CodecResult<json::Value>> {
    instruction.as_any().downcast_ref::<T>().map(render)
}

/// Render `instruction` with the infallible `render` when it is a `T`.
fn render_infallible_as<T: 'static>(
    instruction: &dyn InstructionTrait,
    render: fn(&T) -> json::Value,
) -> Option<CodecResult<json::Value>> {
    instruction
        .as_any()
        .downcast_ref::<T>()
        .map(|typed| Ok(render(typed)))
}

/// Render `instruction` with `render` when it is a `T` in a variant `render` covers.
fn render_variants_as<T: 'static>(
    instruction: &dyn InstructionTrait,
    render: fn(&T) -> CodecResult<Option<json::Value>>,
) -> Option<CodecResult<json::Value>> {
    instruction
        .as_any()
        .downcast_ref::<T>()
        .and_then(|typed| render(typed).transpose())
}

/// Asset transfer control, settlement, Soracloud and code-upload cancellation instructions.
fn asset_instruction_to_json(
    instruction: &dyn InstructionTrait,
) -> Option<CodecResult<json::Value>> {
    render_as(instruction, set_asset_holding_limit_to_json)
        .or_else(|| render_as(instruction, set_asset_transfer_availability_to_json))
        .or_else(|| render_as(instruction, set_asset_transfer_blacklist_to_json))
        .or_else(|| render_as(instruction, set_asset_transfer_control_to_json))
        .or_else(|| render_as(instruction, cancel_smart_contract_code_upload_to_json))
        .or_else(|| render_as(instruction, cancel_asset_lock_to_json))
        .or_else(|| render_as(instruction, deploy_soracloud_service_to_json))
        .or_else(|| render_as(instruction, deploy_soracloud_agent_apartment_to_json))
        .or_else(|| render_as(instruction, join_soracloud_hf_shared_lease_to_json))
        .or_else(|| render_as(instruction, settlement_instruction_box_to_json))
}

/// Generic ledger instructions.
fn ledger_instruction_to_json(
    instruction: &dyn InstructionTrait,
) -> Option<CodecResult<json::Value>> {
    render_variants_as(instruction, register_box_to_json)
        .or_else(|| render_as(instruction, register_dataspace_asset_definition_to_json))
        .or_else(|| render_variants_as(instruction, unregister_box_to_json))
        .or_else(|| render_variants_as(instruction, mint_box_to_json))
        .or_else(|| render_variants_as(instruction, transfer_box_to_json))
        .or_else(|| render_as(instruction, transfer_asset_batch_to_json))
        .or_else(|| render_variants_as(instruction, burn_box_to_json))
        .or_else(|| render_variants_as(instruction, grant_box_to_json))
        .or_else(|| render_variants_as(instruction, set_key_value_box_to_json))
        .or_else(|| render_infallible_as(instruction, set_asset_definition_alias_to_json))
        .or_else(|| render_as(instruction, execute_trigger_to_json))
}

/// RWA instructions, whether boxed or concrete, and custom instructions.
fn rwa_instruction_to_json(instruction: &dyn InstructionTrait) -> Option<CodecResult<json::Value>> {
    render_as(instruction, rwa_instruction_box_to_json)
        .or_else(|| render_as(instruction, custom_instruction_to_json))
        .or_else(|| render_as(instruction, register_rwa_to_json))
        .or_else(|| render_as(instruction, transfer_rwa_to_json))
        .or_else(|| render_as(instruction, merge_rwas_to_json))
        .or_else(|| render_infallible_as(instruction, redeem_rwa_to_json))
        .or_else(|| render_infallible_as(instruction, freeze_rwa_to_json))
        .or_else(|| render_infallible_as(instruction, unfreeze_rwa_to_json))
        .or_else(|| render_infallible_as(instruction, hold_rwa_to_json))
        .or_else(|| render_infallible_as(instruction, release_rwa_to_json))
        .or_else(|| render_as(instruction, force_transfer_rwa_to_json))
        .or_else(|| render_as(instruction, set_rwa_controls_to_json))
}

/// Governance, zk, parameter, smart-contract code and social instructions.
fn governance_instruction_to_json(
    instruction: &dyn InstructionTrait,
) -> Option<CodecResult<json::Value>> {
    render_infallible_as(instruction, submit_agenda_proposal_to_json)
        .or_else(|| render_as(instruction, propose_validation_fee_policy_to_json))
        .or_else(|| render_as(instruction, propose_deploy_contract_to_json))
        .or_else(|| render_infallible_as(instruction, cast_zk_ballot_to_json))
        .or_else(|| render_as(instruction, register_citizen_to_json))
        .or_else(|| render_as(instruction, register_zk_asset_to_json))
        .or_else(|| render_as(instruction, schedule_confidential_policy_transition_to_json))
        .or_else(|| render_as(instruction, cancel_confidential_policy_transition_to_json))
        .or_else(|| render_as(instruction, create_election_to_json))
        .or_else(|| render_as(instruction, submit_ballot_to_json))
        .or_else(|| render_as(instruction, finalize_election_to_json))
        .or_else(|| render_as(instruction, set_parameter_to_json))
        .or_else(|| render_as(instruction, register_smart_contract_code_to_json))
        .or_else(|| render_as(instruction, register_smart_contract_bytes_to_json))
        .or_else(|| render_as(instruction, remove_smart_contract_bytes_to_json))
        .or_else(|| render_as(instruction, claim_twitter_follow_reward_to_json))
        .or_else(|| render_as(instruction, send_to_twitter_to_json))
        .or_else(|| render_as(instruction, cancel_twitter_escrow_to_json))
}

/// Kaigi call and relay instructions.
fn kaigi_instruction_to_json(
    instruction: &dyn InstructionTrait,
) -> Option<CodecResult<json::Value>> {
    render_as(instruction, create_kaigi_to_json)
        .or_else(|| render_as(instruction, join_kaigi_to_json))
        .or_else(|| render_as(instruction, leave_kaigi_to_json))
        .or_else(|| render_as(instruction, end_kaigi_to_json))
        .or_else(|| render_as(instruction, record_kaigi_usage_to_json))
        .or_else(|| render_as(instruction, report_kaigi_relay_health_to_json))
        .or_else(|| render_as(instruction, set_kaigi_relay_manifest_to_json))
        .or_else(|| render_as(instruction, register_kaigi_relay_to_json))
        .or_else(|| render_as(instruction, unregister_kaigi_relay_to_json))
}

/// Render `SetAssetHoldingLimit` through its strict JSON contract.
fn set_asset_holding_limit_to_json(
    limit: &iroha_data_model::isi::asset_transfer_control::SetAssetHoldingLimit,
) -> CodecResult<json::Value> {
    Ok(norito::json!({
        "name": "SetAssetHoldingLimit",
        "params": {
            "account_id": (account_id_to_canonical_i105(&limit.account_id)?),
            "asset_definition_id": (limit.asset_definition_id.to_string()),
            "holding_limit": (limit.holding_limit.as_ref().map(std::string::ToString::to_string)),
        },
    }))
}

/// Render `SetAssetTransferAvailability` through its strict JSON contract.
fn set_asset_transfer_availability_to_json(
    availability: &SetAssetTransferAvailability,
) -> CodecResult<json::Value> {
    let mut inner = json::Map::new();
    inner.insert(
        "account_id".to_owned(),
        json::to_value(&availability.account_id).map_err(codec_error)?,
    );
    inner.insert(
        "asset_definition_id".to_owned(),
        json::to_value(&availability.asset_definition_id).map_err(codec_error)?,
    );
    inner.insert(
        "expected_revision".to_owned(),
        json::Value::String(availability.expected_revision.to_string()),
    );
    inner.insert(
        "incoming".to_owned(),
        json::Value::String(
            match availability.incoming {
                AssetTransferAvailability::Enabled => "Enabled",
                AssetTransferAvailability::Disabled => "Disabled",
            }
            .to_owned(),
        ),
    );
    inner.insert(
        "outgoing".to_owned(),
        json::Value::String(
            match availability.outgoing {
                AssetTransferAvailability::Enabled => "Enabled",
                AssetTransferAvailability::Disabled => "Disabled",
            }
            .to_owned(),
        ),
    );
    inner.insert(
        "reason".to_owned(),
        availability
            .reason
            .as_ref()
            .map_or(json::Value::Null, |value| {
                json::Value::String(value.clone())
            }),
    );
    let mut outer = json::Map::new();
    outer.insert(
        "SetAssetTransferAvailability".to_owned(),
        json::Value::Object(inner),
    );
    Ok(json::Value::Object(outer))
}

/// Render `SetAssetTransferBlacklist` through its strict JSON contract.
fn set_asset_transfer_blacklist_to_json(
    blacklist: &SetAssetTransferBlacklist,
) -> CodecResult<json::Value> {
    let mut inner = json::Map::new();
    inner.insert(
        "account_id".to_owned(),
        json::to_value(&blacklist.account_id).map_err(codec_error)?,
    );
    inner.insert(
        "asset_definition_id".to_owned(),
        json::to_value(&blacklist.asset_definition_id).map_err(codec_error)?,
    );
    inner.insert(
        "blacklisted".to_owned(),
        json::Value::Bool(blacklist.blacklisted),
    );
    let mut outer = json::Map::new();
    outer.insert(
        "SetAssetTransferBlacklist".to_owned(),
        json::Value::Object(inner),
    );
    Ok(json::Value::Object(outer))
}

/// Render `SetAssetTransferControl` through its strict JSON contract.
fn set_asset_transfer_control_to_json(
    control: &SetAssetTransferControl,
) -> CodecResult<json::Value> {
    let mut inner = json::Map::new();
    inner.insert(
        "account_id".to_owned(),
        json::to_value(&control.account_id).map_err(codec_error)?,
    );
    inner.insert(
        "asset_definition_id".to_owned(),
        json::to_value(&control.asset_definition_id).map_err(codec_error)?,
    );
    inner.insert(
        "limits".to_owned(),
        json::Value::Array(
            control
                .limits
                .iter()
                .map(|limit| {
                    let mut fields = json::Map::new();
                    fields.insert(
                        "window".to_owned(),
                        json::Value::String(
                            match limit.window {
                                AssetTransferControlWindow::Day => "Day",
                                AssetTransferControlWindow::Week => "Week",
                                AssetTransferControlWindow::Month => "Month",
                            }
                            .to_owned(),
                        ),
                    );
                    fields.insert(
                        "cap_amount".to_owned(),
                        limit
                            .cap_amount
                            .as_ref()
                            .map_or(json::Value::Null, |value| {
                                json::Value::String(value.to_string())
                            }),
                    );
                    json::Value::Object(fields)
                })
                .collect(),
        ),
    );
    let mut outer = json::Map::new();
    outer.insert(
        "SetAssetTransferControl".to_owned(),
        json::Value::Object(inner),
    );
    Ok(json::Value::Object(outer))
}

/// Render `CancelSmartContractCodeUpload` through its strict JSON contract.
fn cancel_smart_contract_code_upload_to_json(
    cancel: &CancelSmartContractCodeUpload,
) -> CodecResult<json::Value> {
    Ok(json::Value::Object(
        [(
            "CancelSmartContractCodeUpload".to_owned(),
            json::Value::Object(
                [(
                    "artifact_id".to_owned(),
                    lifecycle_instructions::render_artifact_id(&cancel.artifact_id)?,
                )]
                .into_iter()
                .collect(),
            ),
        )]
        .into_iter()
        .collect(),
    ))
}

/// Render `CancelAssetLock` through its strict JSON contract.
fn cancel_asset_lock_to_json(cancel: &CancelAssetLock) -> CodecResult<json::Value> {
    if cancel.expected_remaining_amount.is_zero() {
        return Err(CodecError::new(
            CodecErrorKind::InvalidArgument,
            "CancelAssetLock.expected_remaining_amount must be positive",
        ));
    }
    let mut inner = json::Map::new();
    inner.insert(
        "escrow_id".to_owned(),
        json::to_value(&cancel.escrow_id).map_err(codec_error)?,
    );
    inner.insert(
        "expected_remaining_amount".to_owned(),
        json::Value::String(cancel.expected_remaining_amount.to_string()),
    );
    let mut outer = json::Map::new();
    outer.insert("CancelAssetLock".to_owned(), json::Value::Object(inner));
    Ok(json::Value::Object(outer))
}

/// Render `DeploySoracloudService` through its strict JSON contract.
fn deploy_soracloud_service_to_json(
    deploy: &iroha_data_model::isi::soracloud::DeploySoracloudService,
) -> CodecResult<json::Value> {
    let mut outer = json::Map::new();
    outer.insert(
        "DeploySoracloudService".to_owned(),
        json::to_value(deploy).map_err(codec_error)?,
    );
    Ok(json::Value::Object(outer))
}

/// Render `DeploySoracloudAgentApartment` through its strict JSON contract.
fn deploy_soracloud_agent_apartment_to_json(
    deploy: &iroha_data_model::isi::soracloud::DeploySoracloudAgentApartment,
) -> CodecResult<json::Value> {
    let mut outer = json::Map::new();
    outer.insert(
        "DeploySoracloudAgentApartment".to_owned(),
        json::to_value(deploy).map_err(codec_error)?,
    );
    Ok(json::Value::Object(outer))
}

/// Render `JoinSoracloudHfSharedLease` through its strict JSON contract.
fn join_soracloud_hf_shared_lease_to_json(
    join: &iroha_data_model::isi::soracloud::JoinSoracloudHfSharedLease,
) -> CodecResult<json::Value> {
    let mut outer = json::Map::new();
    outer.insert(
        "JoinSoracloudHfSharedLease".to_owned(),
        json::to_value(join).map_err(codec_error)?,
    );
    Ok(json::Value::Object(outer))
}

/// Render `SettlementInstructionBox` through its strict JSON contract.
fn settlement_instruction_box_to_json(
    settlement: &SettlementInstructionBox,
) -> CodecResult<json::Value> {
    let (variant, payload) = match settlement {
        SettlementInstructionBox::Atomic(value) => {
            ("Atomic", json::to_value(value).map_err(codec_error)?)
        }
        SettlementInstructionBox::Dvp(value) => {
            ("Dvp", json::to_value(value).map_err(codec_error)?)
        }
        SettlementInstructionBox::Pvp(value) => {
            ("Pvp", json::to_value(value).map_err(codec_error)?)
        }
        SettlementInstructionBox::SetFxCorridorPolicy(value) => (
            "SetFxCorridorPolicy",
            json::to_value(value).map_err(codec_error)?,
        ),
        SettlementInstructionBox::FundFxCorridorEscrow(value) => (
            "FundFxCorridorEscrow",
            json::to_value(value).map_err(codec_error)?,
        ),
        SettlementInstructionBox::RefundFxCorridorEscrow(value) => (
            "RefundFxCorridorEscrow",
            json::to_value(value).map_err(codec_error)?,
        ),
        SettlementInstructionBox::SettleFxCorridor(value) => (
            "SettleFxCorridor",
            json::to_value(value).map_err(codec_error)?,
        ),
    };
    let mut variants = json::Map::new();
    variants.insert(variant.to_owned(), payload);
    let mut outer = json::Map::new();
    outer.insert("Settlement".to_owned(), json::Value::Object(variants));
    Ok(json::Value::Object(outer))
}

/// Render the `RegisterBox` variants that have a strict JSON contract.
fn register_box_to_json(register_box: &RegisterBox) -> CodecResult<Option<json::Value>> {
    let mut register_map = json::Map::new();
    match register_box {
        RegisterBox::Domain(register) => {
            let inner = json::to_value(register.object()).map_err(codec_error)?;
            register_map.insert("Domain".to_owned(), inner);
        }
        RegisterBox::Account(register) => {
            let inner = json::to_value(register.object()).map_err(codec_error)?;
            register_map.insert("Account".to_owned(), inner);
        }
        RegisterBox::AssetDefinition(register) => {
            let inner = json::to_value(register.object()).map_err(codec_error)?;
            register_map.insert("AssetDefinition".to_owned(), inner);
        }
        RegisterBox::Nft(register) => {
            let inner = json::to_value(register.object()).map_err(codec_error)?;
            register_map.insert("Nft".to_owned(), inner);
        }
        RegisterBox::Role(register) => {
            let inner = json::to_value(register.object()).map_err(codec_error)?;
            register_map.insert("Role".to_owned(), inner);
        }
        RegisterBox::Trigger(register) => {
            let trigger = register.object();
            let mut inner = json::Map::new();
            inner.insert(
                "id".to_owned(),
                json::to_value(trigger.id()).map_err(codec_error)?,
            );
            inner.insert(
                "action".to_owned(),
                json::to_value(trigger.action()).map_err(codec_error)?,
            );
            register_map.insert("Trigger".to_owned(), json::Value::Object(inner));
        }
        RegisterBox::Peer(register) => {
            let inner = json::to_value(register).map_err(codec_error)?;
            register_map.insert("Peer".to_owned(), inner);
        }
    }
    if !register_map.is_empty() {
        let mut outer = json::Map::new();
        outer.insert("Register".to_owned(), json::Value::Object(register_map));
        return Ok(Some(json::Value::Object(outer)));
    }
    Ok(None)
}

/// Render the `UnregisterBox` variants that have a strict JSON contract.
fn unregister_box_to_json(unregister_box: &UnregisterBox) -> CodecResult<Option<json::Value>> {
    let mut unregister_map = json::Map::new();
    match unregister_box {
        UnregisterBox::Peer(unregister) => {
            let inner = json::to_value(&unregister.object).map_err(codec_error)?;
            unregister_map.insert("Peer".to_owned(), inner);
        }
        UnregisterBox::Domain(unregister) => {
            let inner = json::to_value(&unregister.object).map_err(codec_error)?;
            unregister_map.insert("Domain".to_owned(), inner);
        }
        UnregisterBox::Account(unregister) => {
            let inner = json::to_value(&unregister.object).map_err(codec_error)?;
            unregister_map.insert("Account".to_owned(), inner);
        }
        UnregisterBox::AssetDefinition(unregister) => {
            let inner = json::to_value(&unregister.object).map_err(codec_error)?;
            unregister_map.insert("AssetDefinition".to_owned(), inner);
        }
        UnregisterBox::Nft(unregister) => {
            let inner = json::to_value(&unregister.object).map_err(codec_error)?;
            unregister_map.insert("Nft".to_owned(), inner);
        }
        UnregisterBox::Role(unregister) => {
            let inner = json::to_value(&unregister.object).map_err(codec_error)?;
            unregister_map.insert("Role".to_owned(), inner);
        }
        UnregisterBox::Trigger(unregister) => {
            let inner = json::to_value(&unregister.object).map_err(codec_error)?;
            unregister_map.insert("Trigger".to_owned(), inner);
        }
    }
    if !unregister_map.is_empty() {
        let mut outer = json::Map::new();
        outer.insert("Unregister".to_owned(), json::Value::Object(unregister_map));
        return Ok(Some(json::Value::Object(outer)));
    }
    Ok(None)
}

/// Render the `MintBox` variants that have a strict JSON contract.
fn mint_box_to_json(mint_box: &MintBox) -> CodecResult<Option<json::Value>> {
    let mut mint_map = json::Map::new();
    if let MintBox::Asset(mint) = mint_box {
        let mut asset_fields = json::Map::new();
        let object = json::to_value(mint.object()).map_err(codec_error)?;
        let destination = json::Value::String(mint.destination().canonical_literal());
        asset_fields.insert("object".to_owned(), object);
        asset_fields.insert("destination".to_owned(), destination);
        mint_map.insert("Asset".to_owned(), json::Value::Object(asset_fields));
    }
    if let MintBox::TriggerRepetitions(mint) = mint_box {
        let mut trigger_fields = json::Map::new();
        let repetitions = json::to_value(mint.object()).map_err(codec_error)?;
        let destination = json::to_value(mint.destination()).map_err(codec_error)?;
        trigger_fields.insert("object".to_owned(), repetitions);
        trigger_fields.insert("destination".to_owned(), destination);
        mint_map.insert(
            "TriggerRepetitions".to_owned(),
            json::Value::Object(trigger_fields),
        );
    }
    if !mint_map.is_empty() {
        let mut outer = json::Map::new();
        outer.insert("Mint".to_owned(), json::Value::Object(mint_map));
        return Ok(Some(json::Value::Object(outer)));
    }
    Ok(None)
}

/// Render the `TransferBox` variants that have a strict JSON contract.
fn transfer_box_to_json(transfer_box: &TransferBox) -> CodecResult<Option<json::Value>> {
    let mut transfer_map = json::Map::new();
    if let TransferBox::Asset(transfer) = transfer_box {
        let mut asset_fields = json::Map::new();
        let source = json::Value::String(transfer.source().canonical_literal());
        let quantity = json::to_value(transfer.object()).map_err(codec_error)?;
        let destination = json::to_value(transfer.destination()).map_err(codec_error)?;
        asset_fields.insert("source".to_owned(), source);
        asset_fields.insert("object".to_owned(), quantity);
        asset_fields.insert("destination".to_owned(), destination);
        transfer_map.insert("Asset".to_owned(), json::Value::Object(asset_fields));
    }
    if let TransferBox::Domain(transfer) = transfer_box {
        let mut domain_fields = json::Map::new();
        let source = json::to_value(transfer.source()).map_err(codec_error)?;
        let object = json::to_value(transfer.object()).map_err(codec_error)?;
        let destination = json::to_value(transfer.destination()).map_err(codec_error)?;
        domain_fields.insert("source".to_owned(), source);
        domain_fields.insert("object".to_owned(), object);
        domain_fields.insert("destination".to_owned(), destination);
        transfer_map.insert("Domain".to_owned(), json::Value::Object(domain_fields));
    }
    if let TransferBox::AssetDefinition(transfer) = transfer_box {
        let mut definition_fields = json::Map::new();
        let source = json::to_value(transfer.source()).map_err(codec_error)?;
        let object = json::to_value(transfer.object()).map_err(codec_error)?;
        let destination = json::to_value(transfer.destination()).map_err(codec_error)?;
        definition_fields.insert("source".to_owned(), source);
        definition_fields.insert("object".to_owned(), object);
        definition_fields.insert("destination".to_owned(), destination);
        transfer_map.insert(
            "AssetDefinition".to_owned(),
            json::Value::Object(definition_fields),
        );
    }
    if let TransferBox::Nft(transfer) = transfer_box {
        let mut nft_fields = json::Map::new();
        let source = json::to_value(transfer.source()).map_err(codec_error)?;
        let object = json::to_value(transfer.object()).map_err(codec_error)?;
        let destination = json::to_value(transfer.destination()).map_err(codec_error)?;
        nft_fields.insert("source".to_owned(), source);
        nft_fields.insert("object".to_owned(), object);
        nft_fields.insert("destination".to_owned(), destination);
        transfer_map.insert("Nft".to_owned(), json::Value::Object(nft_fields));
    }
    if !transfer_map.is_empty() {
        let mut outer = json::Map::new();
        outer.insert("Transfer".to_owned(), json::Value::Object(transfer_map));
        return Ok(Some(json::Value::Object(outer)));
    }
    Ok(None)
}

/// Render `TransferAssetBatch` through its strict JSON contract.
fn transfer_asset_batch_to_json(batch: &TransferAssetBatch) -> CodecResult<json::Value> {
    let mut outer = json::Map::new();
    outer.insert(
        "TransferAssetBatch".to_owned(),
        json::to_value(batch).map_err(codec_error)?,
    );
    Ok(json::Value::Object(outer))
}

/// Render the `BurnBox` variants that have a strict JSON contract.
fn burn_box_to_json(burn_box: &BurnBox) -> CodecResult<Option<json::Value>> {
    let mut burn_map = json::Map::new();
    if let BurnBox::Asset(burn) = burn_box {
        let mut asset_fields = json::Map::new();
        let object = json::to_value(burn.object()).map_err(codec_error)?;
        let destination = json::Value::String(burn.destination().canonical_literal());
        asset_fields.insert("object".to_owned(), object);
        asset_fields.insert("destination".to_owned(), destination);
        burn_map.insert("Asset".to_owned(), json::Value::Object(asset_fields));
    }
    if let BurnBox::TriggerRepetitions(burn) = burn_box {
        let mut trigger_fields = json::Map::new();
        let repetitions = json::to_value(burn.object()).map_err(codec_error)?;
        let destination = json::to_value(burn.destination()).map_err(codec_error)?;
        trigger_fields.insert("object".to_owned(), repetitions);
        trigger_fields.insert("destination".to_owned(), destination);
        burn_map.insert(
            "TriggerRepetitions".to_owned(),
            json::Value::Object(trigger_fields),
        );
    }
    if !burn_map.is_empty() {
        let mut outer = json::Map::new();
        outer.insert("Burn".to_owned(), json::Value::Object(burn_map));
        return Ok(Some(json::Value::Object(outer)));
    }
    Ok(None)
}

/// Render the `GrantBox` variants that have a strict JSON contract.
fn grant_box_to_json(grant_box: &GrantBox) -> CodecResult<Option<json::Value>> {
    let GrantBox::Permission(grant) = grant_box else {
        return Ok(None);
    };
    let mut fields = json::Map::new();
    fields.insert(
        "object".to_owned(),
        json::to_value(grant.object()).map_err(codec_error)?,
    );
    fields.insert(
        "destination".to_owned(),
        json::to_value(grant.destination()).map_err(codec_error)?,
    );
    let mut grant_map = json::Map::new();
    grant_map.insert("Permission".to_owned(), json::Value::Object(fields));
    let mut outer = json::Map::new();
    outer.insert("Grant".to_owned(), json::Value::Object(grant_map));
    Ok(Some(json::Value::Object(outer)))
}

/// Render the `SetKeyValueBox` variants that have a strict JSON contract.
fn set_key_value_box_to_json(set_key_value: &SetKeyValueBox) -> CodecResult<Option<json::Value>> {
    if let SetKeyValueBox::Account(set) = set_key_value {
        let mut fields = json::Map::new();
        fields.insert(
            "object".to_owned(),
            json::Value::String(account_id_to_canonical_i105(set.object())?),
        );
        fields.insert(
            "key".to_owned(),
            json::to_value(set.key()).map_err(codec_error)?,
        );
        fields.insert(
            "value".to_owned(),
            json::to_value(set.value()).map_err(codec_error)?,
        );
        let mut variants = json::Map::new();
        variants.insert("Account".to_owned(), json::Value::Object(fields));
        let mut outer = json::Map::new();
        outer.insert("SetKeyValue".to_owned(), json::Value::Object(variants));
        return Ok(Some(json::Value::Object(outer)));
    }
    if let SetKeyValueBox::Nft(set) = set_key_value {
        let mut fields = json::Map::new();
        fields.insert(
            "object".to_owned(),
            json::to_value(set.object()).map_err(codec_error)?,
        );
        fields.insert(
            "key".to_owned(),
            json::to_value(set.key()).map_err(codec_error)?,
        );
        fields.insert(
            "value".to_owned(),
            json::to_value(set.value()).map_err(codec_error)?,
        );
        let mut variants = json::Map::new();
        variants.insert("Nft".to_owned(), json::Value::Object(fields));
        let mut outer = json::Map::new();
        outer.insert("SetKeyValue".to_owned(), json::Value::Object(variants));
        return Ok(Some(json::Value::Object(outer)));
    }
    Ok(None)
}

/// Render a direct-dataspace registration without narrowing its dataspace ID.
fn register_dataspace_asset_definition_to_json(
    registration: &RegisterDataspaceAssetDefinition,
) -> CodecResult<json::Value> {
    registration
        .validate()
        .map_err(|error| CodecError::new(CodecErrorKind::InvalidArgument, error.to_string()))?;
    Ok(instruction_envelope(
        "RegisterDataspaceAssetDefinition",
        json::to_value(registration).map_err(codec_error)?,
    ))
}

/// Render `SetAssetDefinitionAlias` through its strict JSON contract.
fn set_asset_definition_alias_to_json(alias: &SetAssetDefinitionAlias) -> json::Value {
    let mut fields = json::Map::new();
    fields.insert(
        "asset_definition_id".to_owned(),
        json::Value::String(alias.asset_definition_id().to_string()),
    );
    fields.insert(
        "alias".to_owned(),
        alias.alias().as_ref().map_or(json::Value::Null, |value| {
            json::Value::String(value.to_string())
        }),
    );
    fields.insert(
        "lease_expiry_ms".to_owned(),
        alias
            .lease_expiry_ms()
            .as_ref()
            .map_or(json::Value::Null, |value| {
                json::Value::Number(json::Number::from(*value))
            }),
    );
    let mut outer = json::Map::new();
    outer.insert(
        "SetAssetDefinitionAlias".to_owned(),
        json::Value::Object(fields),
    );
    json::Value::Object(outer)
}

/// Render `ExecuteTrigger` through its strict JSON contract.
fn execute_trigger_to_json(execute_trigger: &ExecuteTrigger) -> CodecResult<json::Value> {
    let mut payload = json::Map::new();
    payload.insert(
        "trigger".to_owned(),
        json::to_value(execute_trigger.trigger()).map_err(codec_error)?,
    );
    let args = json::parse_value(execute_trigger.args().get()).map_err(|error| {
        CodecError::new(
            CodecErrorKind::InvalidArgument,
            format!("ExecuteTrigger.args is not valid JSON: {error}"),
        )
    })?;
    payload.insert("args".to_owned(), args);
    let mut outer = json::Map::new();
    outer.insert("ExecuteTrigger".to_owned(), json::Value::Object(payload));
    Ok(json::Value::Object(outer))
}

/// Render `RwaInstructionBox` through its strict JSON contract.
fn rwa_instruction_box_to_json(rwa_box: &RwaInstructionBox) -> CodecResult<json::Value> {
    let (label, payload) = match rwa_box {
        RwaInstructionBox::Register(register) => (
            "RegisterRwa",
            norito_json!({ "rwa": new_rwa_to_json(register.rwa())? }),
        ),
        RwaInstructionBox::Transfer(transfer) => (
            "TransferRwa",
            norito_json!({
                "source": account_id_to_canonical_i105(transfer.source())?,
                "rwa": transfer.rwa().to_string(),
                "quantity": transfer.quantity(),
                "destination": account_id_to_canonical_i105(transfer.destination())?,
            }),
        ),
        RwaInstructionBox::Merge(merge) => ("MergeRwas", merge_rwas_payload(merge)?),
        RwaInstructionBox::Redeem(redeem) => (
            "RedeemRwa",
            norito_json!({
                "rwa": redeem.rwa().to_string(),
                "quantity": redeem.quantity(),
            }),
        ),
        RwaInstructionBox::Freeze(freeze) => (
            "FreezeRwa",
            norito_json!({ "rwa": freeze.rwa().to_string() }),
        ),
        RwaInstructionBox::Unfreeze(unfreeze) => (
            "UnfreezeRwa",
            norito_json!({ "rwa": unfreeze.rwa().to_string() }),
        ),
        RwaInstructionBox::Hold(hold) => (
            "HoldRwa",
            norito_json!({
                "rwa": hold.rwa().to_string(),
                "quantity": hold.quantity(),
            }),
        ),
        RwaInstructionBox::Release(release) => (
            "ReleaseRwa",
            norito_json!({
                "rwa": release.rwa().to_string(),
                "quantity": release.quantity(),
            }),
        ),
        RwaInstructionBox::ForceTransfer(force_transfer) => (
            "ForceTransferRwa",
            norito_json!({
                "rwa": force_transfer.rwa().to_string(),
                "quantity": force_transfer.quantity(),
                "destination": account_id_to_canonical_i105(force_transfer.destination())?,
            }),
        ),
        RwaInstructionBox::SetControls(set_controls) => (
            "SetRwaControls",
            norito_json!({
                "rwa": set_controls.rwa().to_string(),
                "controls": rwa_control_policy_to_json(set_controls.controls())?,
            }),
        ),
        RwaInstructionBox::SetKeyValue(set) => (
            "SetRwaKeyValue",
            norito_json!({
                "rwa": set.object().to_string(),
                "key": set.key().clone(),
                "value": json::to_value(set.value()).map_err(codec_error)?,
            }),
        ),
        RwaInstructionBox::RemoveKeyValue(remove) => (
            "RemoveRwaKeyValue",
            norito_json!({
                "rwa": remove.object().to_string(),
                "key": remove.key().clone(),
            }),
        ),
    };
    let mut outer = json::Map::new();
    outer.insert(label.to_owned(), payload);
    Ok(json::Value::Object(outer))
}

/// Render `CustomInstruction` through its strict JSON contract.
fn custom_instruction_to_json(custom_instruction: &CustomInstruction) -> CodecResult<json::Value> {
    let payload_json = json::parse_value(custom_instruction.payload.get()).map_err(|error| {
        CodecError::new(
            CodecErrorKind::InvalidArgument,
            format!("Custom.payload is not valid JSON: {error}"),
        )
    })?;
    Ok(custom_json_value(payload_json))
}

/// Render `RegisterRwa` through its strict JSON contract.
fn register_rwa_to_json(register: &RegisterRwa) -> CodecResult<json::Value> {
    let mut outer = json::Map::new();
    outer.insert(
        "RegisterRwa".to_owned(),
        norito_json!({ "rwa": new_rwa_to_json(register.rwa())? }),
    );
    Ok(json::Value::Object(outer))
}

/// Render `TransferRwa` through its strict JSON contract.
fn transfer_rwa_to_json(transfer: &TransferRwa) -> CodecResult<json::Value> {
    let mut outer = json::Map::new();
    outer.insert(
        "TransferRwa".to_owned(),
        norito_json!({
            "source": account_id_to_canonical_i105(transfer.source())?,
            "rwa": transfer.rwa().to_string(),
            "quantity": transfer.quantity(),
            "destination": account_id_to_canonical_i105(transfer.destination())?,
        }),
    );
    Ok(json::Value::Object(outer))
}

/// Render `MergeRwas` through its strict JSON contract.
fn merge_rwas_to_json(merge: &MergeRwas) -> CodecResult<json::Value> {
    let mut outer = json::Map::new();
    outer.insert("MergeRwas".to_owned(), merge_rwas_payload(merge)?);
    Ok(json::Value::Object(outer))
}

/// Render the `MergeRwas` payload shared by the boxed and concrete instruction forms.
fn merge_rwas_payload(merge: &MergeRwas) -> CodecResult<json::Value> {
    let mut payload = json::Map::new();
    payload.insert(
        "parents".to_owned(),
        rwa_parent_refs_to_json(merge.parents()),
    );
    payload.insert(
        "primary_reference".to_owned(),
        json::Value::String(merge.primary_reference().clone()),
    );
    payload.insert(
        "status".to_owned(),
        rwa_status_to_json(merge.status().as_ref()),
    );
    payload.insert(
        "metadata".to_owned(),
        json::to_value(merge.metadata()).map_err(codec_error)?,
    );
    Ok(json::Value::Object(payload))
}

/// Render `RedeemRwa` through its strict JSON contract.
fn redeem_rwa_to_json(redeem: &RedeemRwa) -> json::Value {
    let mut outer = json::Map::new();
    outer.insert(
        "RedeemRwa".to_owned(),
        norito_json!({
            "rwa": redeem.rwa().to_string(),
            "quantity": redeem.quantity(),
        }),
    );
    json::Value::Object(outer)
}

/// Render `FreezeRwa` through its strict JSON contract.
fn freeze_rwa_to_json(freeze: &FreezeRwa) -> json::Value {
    let mut outer = json::Map::new();
    outer.insert(
        "FreezeRwa".to_owned(),
        norito_json!({ "rwa": freeze.rwa().to_string() }),
    );
    json::Value::Object(outer)
}

/// Render `UnfreezeRwa` through its strict JSON contract.
fn unfreeze_rwa_to_json(unfreeze: &UnfreezeRwa) -> json::Value {
    let mut outer = json::Map::new();
    outer.insert(
        "UnfreezeRwa".to_owned(),
        norito_json!({ "rwa": unfreeze.rwa().to_string() }),
    );
    json::Value::Object(outer)
}

/// Render `HoldRwa` through its strict JSON contract.
fn hold_rwa_to_json(hold: &HoldRwa) -> json::Value {
    let mut outer = json::Map::new();
    outer.insert(
        "HoldRwa".to_owned(),
        norito_json!({
            "rwa": hold.rwa().to_string(),
            "quantity": hold.quantity(),
        }),
    );
    json::Value::Object(outer)
}

/// Render `ReleaseRwa` through its strict JSON contract.
fn release_rwa_to_json(release: &ReleaseRwa) -> json::Value {
    let mut outer = json::Map::new();
    outer.insert(
        "ReleaseRwa".to_owned(),
        norito_json!({
            "rwa": release.rwa().to_string(),
            "quantity": release.quantity(),
        }),
    );
    json::Value::Object(outer)
}

/// Render `ForceTransferRwa` through its strict JSON contract.
fn force_transfer_rwa_to_json(force_transfer: &ForceTransferRwa) -> CodecResult<json::Value> {
    let mut outer = json::Map::new();
    outer.insert(
        "ForceTransferRwa".to_owned(),
        norito_json!({
            "rwa": force_transfer.rwa().to_string(),
            "quantity": force_transfer.quantity(),
            "destination": account_id_to_canonical_i105(force_transfer.destination())?,
        }),
    );
    Ok(json::Value::Object(outer))
}

/// Render `SetRwaControls` through its strict JSON contract.
fn set_rwa_controls_to_json(set_controls: &SetRwaControls) -> CodecResult<json::Value> {
    let mut outer = json::Map::new();
    outer.insert(
        "SetRwaControls".to_owned(),
        norito_json!({
            "rwa": set_controls.rwa().to_string(),
            "controls": rwa_control_policy_to_json(set_controls.controls())?,
        }),
    );
    Ok(json::Value::Object(outer))
}

/// Render `SubmitAgendaProposal` through its strict JSON contract.
fn submit_agenda_proposal_to_json(submit: &SubmitAgendaProposal) -> json::Value {
    let mut outer = json::Map::new();
    outer.insert(
        "SubmitAgendaProposal".to_owned(),
        norito_json!({
            "proposal": submit.proposal,
        }),
    );
    json::Value::Object(outer)
}

/// Render `ProposeValidationFeePolicy` through its strict JSON contract.
fn propose_validation_fee_policy_to_json(
    propose: &ProposeValidationFeePolicy,
) -> CodecResult<json::Value> {
    let mut inner = json::Map::new();
    inner.insert(
        "policy".to_owned(),
        json::to_value(&propose.policy).map_err(codec_error)?,
    );
    let mut outer = json::Map::new();
    outer.insert(
        "ProposeValidationFeePolicy".to_owned(),
        json::Value::Object(inner),
    );
    Ok(json::Value::Object(outer))
}

/// Render `ProposeDeployContract` through its strict JSON contract.
fn propose_deploy_contract_to_json(propose: &ProposeDeployContract) -> CodecResult<json::Value> {
    let mut inner = json::Map::new();
    inner.insert(
        "contract_address".to_owned(),
        json::Value::String(propose.contract_address.to_string()),
    );
    inner.insert(
        "code_hash".to_owned(),
        json::to_value(&propose.code_hash).map_err(codec_error)?,
    );
    inner.insert(
        "abi_hash".to_owned(),
        json::to_value(&propose.abi_hash).map_err(codec_error)?,
    );
    inner.insert(
        "abi_version".to_owned(),
        json::to_value(&propose.abi_version).map_err(codec_error)?,
    );
    if let Some(manifest_provenance) = &propose.manifest_provenance {
        inner.insert(
            "manifest_provenance".to_owned(),
            json::to_value(manifest_provenance).map_err(codec_error)?,
        );
    }
    let mut outer = json::Map::new();
    outer.insert(
        "ProposeDeployContract".to_owned(),
        json::Value::Object(inner),
    );
    Ok(json::Value::Object(outer))
}

/// Render `CastZkBallot` through its strict JSON contract.
fn cast_zk_ballot_to_json(ballot: &CastZkBallot) -> json::Value {
    let mut inner = json::Map::new();
    inner.insert(
        "election_id".to_owned(),
        json::Value::String(ballot.election_id.clone()),
    );
    inner.insert(
        "proof_b64".to_owned(),
        json::Value::String(ballot.proof_b64.clone()),
    );
    inner.insert(
        "public_inputs_json".to_owned(),
        json::Value::String(ballot.public_inputs_json.clone()),
    );
    let mut outer = json::Map::new();
    outer.insert("CastZkBallot".to_owned(), json::Value::Object(inner));
    json::Value::Object(outer)
}

/// Render `RegisterCitizen` through its strict JSON contract.
fn register_citizen_to_json(citizen: &RegisterCitizen) -> CodecResult<json::Value> {
    let mut inner = json::Map::new();
    inner.insert(
        "owner".to_owned(),
        json::to_value(&citizen.owner).map_err(codec_error)?,
    );
    inner.insert(
        "amount".to_owned(),
        json::Value::String(citizen.amount.to_string()),
    );
    let mut outer = json::Map::new();
    outer.insert("RegisterCitizen".to_owned(), json::Value::Object(inner));
    Ok(json::Value::Object(outer))
}

/// Render `RegisterZkAsset` through its strict JSON contract.
fn register_zk_asset_to_json(register: &RegisterZkAsset) -> CodecResult<json::Value> {
    Ok(zk_json_value(
        "RegisterZkAsset",
        json::to_value(register).map_err(codec_error)?,
    ))
}

/// Render `ScheduleConfidentialPolicyTransition` through its strict JSON contract.
fn schedule_confidential_policy_transition_to_json(
    transition: &ScheduleConfidentialPolicyTransition,
) -> CodecResult<json::Value> {
    Ok(zk_json_value(
        "ScheduleConfidentialPolicyTransition",
        json::to_value(transition).map_err(codec_error)?,
    ))
}

/// Render `CancelConfidentialPolicyTransition` through its strict JSON contract.
fn cancel_confidential_policy_transition_to_json(
    cancel: &CancelConfidentialPolicyTransition,
) -> CodecResult<json::Value> {
    Ok(zk_json_value(
        "CancelConfidentialPolicyTransition",
        json::to_value(cancel).map_err(codec_error)?,
    ))
}

/// Render `CreateElection` through its strict JSON contract.
fn create_election_to_json(create: &CreateElection) -> CodecResult<json::Value> {
    Ok(zk_json_value(
        "CreateElection",
        json::to_value(create).map_err(codec_error)?,
    ))
}

/// Render `SubmitBallot` through its strict JSON contract.
fn submit_ballot_to_json(submit: &SubmitBallot) -> CodecResult<json::Value> {
    Ok(zk_json_value(
        "SubmitBallot",
        json::to_value(submit).map_err(codec_error)?,
    ))
}

/// Render `FinalizeElection` through its strict JSON contract.
fn finalize_election_to_json(finalize: &FinalizeElection) -> CodecResult<json::Value> {
    Ok(zk_json_value(
        "FinalizeElection",
        json::to_value(finalize).map_err(codec_error)?,
    ))
}

/// Render `SetParameter` through its strict JSON contract.
fn set_parameter_to_json(parameter: &SetParameter) -> CodecResult<json::Value> {
    Ok(instruction_envelope(
        "SetParameter",
        json::to_value(&parameter.0).map_err(codec_error)?,
    ))
}

/// Render `RegisterSmartContractCode` through its strict JSON contract.
fn register_smart_contract_code_to_json(
    register_code: &RegisterSmartContractCode,
) -> CodecResult<json::Value> {
    manifest::validate_manifest_schemas(&register_code.manifest)?;
    let manifest_value = json::to_value(&register_code.manifest).map_err(codec_error)?;
    let mut inner = json::Map::new();
    inner.insert("manifest".to_owned(), manifest_value);
    inner.insert(
        "artifact_id".into(),
        lifecycle_instructions::render_artifact_id(&register_code.artifact_id)?,
    );
    let mut outer = json::Map::new();
    outer.insert(
        "RegisterSmartContractCode".to_owned(),
        json::Value::Object(inner),
    );
    Ok(json::Value::Object(outer))
}

/// Render `RegisterSmartContractBytes` through its strict JSON contract.
fn register_smart_contract_bytes_to_json(
    register_bytes: &RegisterSmartContractBytes,
) -> CodecResult<json::Value> {
    let mut inner = json::Map::new();
    inner.insert(
        "artifact_id".to_owned(),
        lifecycle_instructions::render_artifact_id(&register_bytes.artifact_id)?,
    );
    inner.insert(
        "code".to_owned(),
        json::Value::String(STANDARD.encode(&register_bytes.code)),
    );
    let mut outer = json::Map::new();
    outer.insert(
        "RegisterSmartContractBytes".to_owned(),
        json::Value::Object(inner),
    );
    Ok(json::Value::Object(outer))
}

/// Render `RemoveSmartContractBytes` through its strict JSON contract.
fn remove_smart_contract_bytes_to_json(
    remove_bytes: &RemoveSmartContractBytes,
) -> CodecResult<json::Value> {
    let mut inner = json::Map::new();
    inner.insert(
        "artifact_id".to_owned(),
        lifecycle_instructions::render_artifact_id(&remove_bytes.artifact_id)?,
    );
    if let Some(reason) = &remove_bytes.reason {
        inner.insert("reason".to_owned(), json::Value::String(reason.clone()));
    }
    let mut outer = json::Map::new();
    outer.insert(
        "RemoveSmartContractBytes".to_owned(),
        json::Value::Object(inner),
    );
    Ok(json::Value::Object(outer))
}

/// Render `ClaimTwitterFollowReward` through its strict JSON contract.
fn claim_twitter_follow_reward_to_json(
    claim: &ClaimTwitterFollowReward,
) -> CodecResult<json::Value> {
    let mut inner = json::Map::new();
    inner.insert(
        "binding_hash".to_owned(),
        json::to_value(&claim.binding_hash).map_err(codec_error)?,
    );
    let mut outer = json::Map::new();
    outer.insert(
        "ClaimTwitterFollowReward".to_owned(),
        json::Value::Object(inner),
    );
    Ok(json::Value::Object(outer))
}

/// Render `SendToTwitter` through its strict JSON contract.
fn send_to_twitter_to_json(send: &SendToTwitter) -> CodecResult<json::Value> {
    let mut inner = json::Map::new();
    inner.insert(
        "binding_hash".to_owned(),
        json::to_value(&send.binding_hash).map_err(codec_error)?,
    );
    inner.insert(
        "amount".to_owned(),
        json::to_value(&send.amount).map_err(codec_error)?,
    );
    let mut outer = json::Map::new();
    outer.insert("SendToTwitter".to_owned(), json::Value::Object(inner));
    Ok(json::Value::Object(outer))
}

/// Render `CancelTwitterEscrow` through its strict JSON contract.
fn cancel_twitter_escrow_to_json(cancel: &CancelTwitterEscrow) -> CodecResult<json::Value> {
    let mut inner = json::Map::new();
    inner.insert(
        "binding_hash".to_owned(),
        json::to_value(&cancel.binding_hash).map_err(codec_error)?,
    );
    let mut outer = json::Map::new();
    outer.insert("CancelTwitterEscrow".to_owned(), json::Value::Object(inner));
    Ok(json::Value::Object(outer))
}

/// Render `CreateKaigi` through its strict JSON contract.
fn create_kaigi_to_json(create: &CreateKaigi) -> CodecResult<json::Value> {
    let mut payload = json::Map::new();
    payload.insert("call".to_owned(), kaigi::call_json(create.call())?);
    payload.insert(
        "commitment".to_owned(),
        optional_commitment_to_json(create.commitment().as_ref()),
    );
    payload.insert(
        "nullifier".to_owned(),
        optional_nullifier_to_json(create.nullifier().as_ref()),
    );
    payload.insert(
        "roster_root".to_owned(),
        optional_hash_to_json(create.roster_root().as_ref()),
    );
    payload.insert(
        "proof".to_owned(),
        optional_proof_to_json(create.proof().as_ref()),
    );
    Ok(kaigi_json_value(
        "CreateKaigi",
        json::Value::Object(payload),
    ))
}

/// Render `JoinKaigi` through its strict JSON contract.
fn join_kaigi_to_json(join: &JoinKaigi) -> CodecResult<json::Value> {
    let mut payload = json::Map::new();
    payload.insert(
        "call_id".to_owned(),
        json::to_value(join.call_id()).map_err(codec_error)?,
    );
    payload.insert(
        "participant".to_owned(),
        json::to_value(join.participant()).map_err(codec_error)?,
    );
    payload.insert(
        "commitment".to_owned(),
        optional_commitment_to_json(join.commitment().as_ref()),
    );
    payload.insert(
        "nullifier".to_owned(),
        optional_nullifier_to_json(join.nullifier().as_ref()),
    );
    payload.insert(
        "roster_root".to_owned(),
        optional_hash_to_json(join.roster_root().as_ref()),
    );
    payload.insert(
        "proof".to_owned(),
        optional_proof_to_json(join.proof().as_ref()),
    );
    Ok(kaigi_json_value("JoinKaigi", json::Value::Object(payload)))
}

/// Render `LeaveKaigi` through its strict JSON contract.
fn leave_kaigi_to_json(leave: &LeaveKaigi) -> CodecResult<json::Value> {
    let mut payload = json::Map::new();
    payload.insert(
        "call_id".to_owned(),
        json::to_value(leave.call_id()).map_err(codec_error)?,
    );
    payload.insert(
        "participant".to_owned(),
        json::to_value(leave.participant()).map_err(codec_error)?,
    );
    payload.insert(
        "commitment".to_owned(),
        optional_commitment_to_json(leave.commitment().as_ref()),
    );
    payload.insert(
        "nullifier".to_owned(),
        optional_nullifier_to_json(leave.nullifier().as_ref()),
    );
    payload.insert(
        "roster_root".to_owned(),
        optional_hash_to_json(leave.roster_root().as_ref()),
    );
    payload.insert(
        "proof".to_owned(),
        optional_proof_to_json(leave.proof().as_ref()),
    );
    Ok(kaigi_json_value("LeaveKaigi", json::Value::Object(payload)))
}

/// Render `EndKaigi` through its strict JSON contract.
fn end_kaigi_to_json(end: &EndKaigi) -> CodecResult<json::Value> {
    let mut payload = json::Map::new();
    payload.insert(
        "call_id".to_owned(),
        json::to_value(end.call_id()).map_err(codec_error)?,
    );
    payload.insert(
        "ended_at_ms".to_owned(),
        end.ended_at_ms().map_or(json::Value::Null, kaigi::u64_json),
    );
    payload.insert(
        "commitment".to_owned(),
        optional_commitment_to_json(end.commitment().as_ref()),
    );
    payload.insert(
        "nullifier".to_owned(),
        optional_nullifier_to_json(end.nullifier().as_ref()),
    );
    payload.insert(
        "roster_root".to_owned(),
        optional_hash_to_json(end.roster_root().as_ref()),
    );
    payload.insert(
        "proof".to_owned(),
        optional_proof_to_json(end.proof().as_ref()),
    );
    Ok(kaigi_json_value("EndKaigi", json::Value::Object(payload)))
}

/// Render `RecordKaigiUsage` through its strict JSON contract.
fn record_kaigi_usage_to_json(usage: &RecordKaigiUsage) -> CodecResult<json::Value> {
    let mut payload = json::Map::new();
    payload.insert(
        "call_id".to_owned(),
        json::to_value(usage.call_id()).map_err(codec_error)?,
    );
    payload.insert(
        "duration_ms".to_owned(),
        kaigi::u64_json(*usage.duration_ms()),
    );
    payload.insert(
        "billed_gas".to_owned(),
        kaigi::u64_json(*usage.billed_gas()),
    );
    payload.insert(
        "usage_commitment".to_owned(),
        optional_kaigi_scalar_to_json(usage.usage_commitment().as_ref()),
    );
    payload.insert(
        "proof".to_owned(),
        optional_proof_to_json(usage.proof().as_ref()),
    );
    Ok(kaigi_json_value(
        "RecordKaigiUsage",
        json::Value::Object(payload),
    ))
}

/// Render `ReportKaigiRelayHealth` through its strict JSON contract.
fn report_kaigi_relay_health_to_json(health: &ReportKaigiRelayHealth) -> CodecResult<json::Value> {
    let mut payload = json::Map::new();
    payload.insert(
        "call_id".to_owned(),
        json::to_value(&health.call_id).map_err(codec_error)?,
    );
    payload.insert(
        "relay_id".to_owned(),
        json::to_value(&health.relay_id).map_err(codec_error)?,
    );
    payload.insert(
        "status".to_owned(),
        json::to_value(&health.status).map_err(codec_error)?,
    );
    payload.insert(
        "reported_at_ms".to_owned(),
        kaigi::u64_json(health.reported_at_ms),
    );
    payload.insert(
        "notes".to_owned(),
        health
            .notes
            .as_ref()
            .map_or(json::Value::Null, |s| json::Value::String(s.clone())),
    );
    Ok(kaigi_json_value(
        "ReportKaigiRelayHealth",
        json::Value::Object(payload),
    ))
}

/// Render `SetKaigiRelayManifest` through its strict JSON contract.
fn set_kaigi_relay_manifest_to_json(manifest: &SetKaigiRelayManifest) -> CodecResult<json::Value> {
    let mut payload = json::Map::new();
    payload.insert(
        "call_id".to_owned(),
        json::to_value(manifest.call_id()).map_err(codec_error)?,
    );
    payload.insert(
        "relay_manifest".to_owned(),
        manifest
            .relay_manifest()
            .as_ref()
            .map(kaigi::relay_manifest_json)
            .transpose()?
            .unwrap_or(json::Value::Null),
    );
    Ok(kaigi_json_value(
        "SetKaigiRelayManifest",
        json::Value::Object(payload),
    ))
}

/// Render `RegisterKaigiRelay` through its strict JSON contract.
fn register_kaigi_relay_to_json(registration: &RegisterKaigiRelay) -> CodecResult<json::Value> {
    let mut payload = json::Map::new();
    payload.insert(
        "relay".to_owned(),
        json::to_value(registration.relay()).map_err(codec_error)?,
    );
    Ok(kaigi_json_value(
        "RegisterKaigiRelay",
        json::Value::Object(payload),
    ))
}

/// Render `UnregisterKaigiRelay` through its strict JSON contract.
fn unregister_kaigi_relay_to_json(
    unregistration: &UnregisterKaigiRelay,
) -> CodecResult<json::Value> {
    let mut payload = json::Map::new();
    payload.insert(
        "relay_id".to_owned(),
        json::to_value(unregistration.relay_id()).map_err(codec_error)?,
    );
    Ok(kaigi_json_value(
        "UnregisterKaigiRelay",
        json::Value::Object(payload),
    ))
}

fn kaigi_json_value(tag: &str, payload: json::Value) -> json::Value {
    let mut variant = json::Map::new();
    variant.insert(tag.to_owned(), payload);
    let mut outer = json::Map::new();
    outer.insert("Kaigi".to_owned(), json::Value::Object(variant));
    json::Value::Object(outer)
}

/// Wrap an opaque custom payload in the canonical Custom instruction envelope.
pub fn custom_json_value(payload: json::Value) -> json::Value {
    let mut custom = json::Map::new();
    custom.insert("payload".to_owned(), payload);
    let mut outer = json::Map::new();
    outer.insert("Custom".to_owned(), json::Value::Object(custom));
    json::Value::Object(outer)
}

fn zk_json_value(tag: &str, payload: json::Value) -> json::Value {
    let mut variant = json::Map::new();
    variant.insert(tag.to_owned(), payload);
    let mut outer = json::Map::new();
    outer.insert("zk".to_owned(), json::Value::Object(variant));
    json::Value::Object(outer)
}

#[cfg(test)]
mod atomic_settlement_json_tests;
#[cfg(test)]
mod envelope_family_tests;
#[cfg(test)]
mod tests;

mod multisig_contract;
pub use multisig_contract::build_canonical_multisig_contract_call_json;
