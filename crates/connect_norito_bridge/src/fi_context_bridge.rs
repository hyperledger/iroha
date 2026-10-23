//! Narrow C surface for current FI assertions. All four buffers have distinct
//! owners: remote candidate, locally retained request, local checkpoint, local pins.
use super::fi_context_verification::{
    FiContextAssertionExpectation, VerifiedFiContextAssertionV1, verify_fi_context_assertion_v1,
};
use base64::Engine as _;
use iroha_data_model::{
    NetworkId,
    account::{AccountId, address::AccountAddress},
    asset::{
        AssetDefinitionId,
        fi_context::AssetFiContextTargetV1,
        fi_request::{normalize_asset_fi_context_request_v1, normalize_asset_fi_link_target_v1},
    },
    nexus::AxtAssetIncarnationV1,
    sumeragi_finality::MAX_FINALITY_CHECKPOINT_BYTES,
};
use libc::{c_int, c_uchar, c_ulong};
use norito::json::{self, Map, Value};
use std::slice;

const ERR_FI_CONTEXT: c_int = -511;
const MAX_TRUST_BYTES: usize = 32 * 1024;
const MAX_OUTPUT_BYTES: usize = 512 * 1024;

pub(crate) fn text<'a>(value: &'a Map, key: &str, max: usize) -> Result<&'a str, String> {
    let result = value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing FI pin {key}"))?;
    if result.is_empty()
        || result.len() > max
        || result.trim() != result
        || result.chars().any(char::is_control)
    {
        return Err(format!("invalid FI pin {key}"));
    }
    Ok(result)
}
pub(crate) fn raw32(value: &Map, key: &str) -> Result<[u8; 32], String> {
    let value = text(value, key, 64)?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
    {
        return Err("FI pin requires lowercase raw32 hex".into());
    }
    hex::decode(value)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "invalid raw32 FI pin".into())
}
fn account(value: &Map, key: &str) -> Result<AccountId, String> {
    AccountAddress::parse_encoded(text(value, key, 1024)?, None)
        .and_then(|value| value.to_account_id())
        .map_err(|e| e.to_string())
}

/// Reformat native authenticated AccountId JSON for the caller's admitted display
/// prefix without mutating process-global address configuration. This changes no
/// account identity or proof bytes. All values originate from the typed snapshot.
fn display_accounts(value: &mut Value, prefix: u16) -> Result<(), String> {
    match value {
        Value::String(text) => {
            if let Ok(address) = AccountAddress::parse_encoded(text, None) {
                *text = address
                    .to_i105_for_discriminant(prefix)
                    .map_err(|e| e.to_string())?;
            }
        }
        Value::Array(values) => {
            for value in values {
                display_accounts(value, prefix)?;
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                display_accounts(value, prefix)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Closed original trust parser shared by current and continuation verification.
/// The callback cannot replace the original request floor with a cursor selection.
pub(crate) fn with_fi_context_trust<T>(
    original: &[u8],
    trust: &[u8],
    body: impl FnOnce(&FiContextAssertionExpectation<'_>, u16) -> Result<T, String>,
) -> Result<T, String> {
    if trust.is_empty() || trust.len() > MAX_TRUST_BYTES {
        return Err("FI local pins exceed bound".into());
    }
    let value = json::from_slice_value(trust).map_err(|e| e.to_string())?;
    if json::to_vec(&value).map_err(|e| e.to_string())? != trust {
        return Err("FI local pins must be canonical JSON".into());
    }
    let pins = value.as_object().ok_or("FI local pins must be an object")?;
    const KEYS: &[&str] = &[
        "schema",
        "networkId",
        "chainId",
        "checkpointSha256",
        "checkpointHeight",
        "checkpointContextId",
        "assetOwner",
        "assetIncarnation",
        "assetDefinitionId",
        "walletAccountId",
        "uid",
        "fiAccountId",
        "fiParticipant",
        "uidController",
        "runtimeManifestSha256",
        "ownerKeyIdentity",
        "walletScopeCanonical",
        "requestSha256",
        "target",
    ];
    if pins.len() != KEYS.len()
        || KEYS.iter().any(|key| !pins.contains_key(*key))
        || text(pins, "schema", 64)? != "iroha.fi-context-verification-trust.v1"
    {
        return Err("unknown or missing FI local pins".into());
    }
    let request = normalize_asset_fi_context_request_v1(original)?;
    let network = text(pins, "networkId", 74)?
        .parse::<NetworkId>()
        .map_err(|e| e.to_string())?;
    let owner = account(pins, "assetOwner")?;
    let wallet = account(pins, "walletAccountId")?;
    let fi = account(pins, "fiAccountId")?;
    let asset = text(pins, "assetDefinitionId", 128)?
        .parse::<AssetDefinitionId>()
        .map_err(|e| e.to_string())?;
    let AssetFiContextTargetV1::LinkApproval(target) = &request.target else {
        return Err("unsupported FI request kind".into());
    };
    let expected_target = AssetFiContextTargetV1::LinkApproval(normalize_asset_fi_link_target_v1(
        pins.get("target")
            .ok_or("missing independently retained FI target")?,
    )?);
    let controller = match pins.get("uidController") {
        Some(Value::Null) => None,
        Some(Value::String(value)) => Some(
            value
                .parse::<iroha_data_model::smart_contract::ContractAddress>()
                .map_err(|e| e.to_string())?,
        ),
        _ => return Err("invalid independently admitted UID controller".into()),
    };
    if request.original_sha256 != raw32(pins, "requestSha256")?
        || request.asset_id != asset
        || request.wallet != wallet
        || target.link.fi_account_id != fi
        || request.target != expected_target
        || request
            .declared_uid_controller
            .as_ref()
            .is_some_and(|declared| declared != &controller)
        || target
            .link
            .controller
            .as_ref()
            .is_some_and(|value| Some(value) != controller.as_ref())
    {
        return Err("FI original differs from local selection".into());
    }
    let height_text = text(pins, "checkpointHeight", 20)?;
    let height = height_text.parse::<u64>().map_err(|e| e.to_string())?;
    if height.to_string() != height_text {
        return Err("noncanonical FI checkpoint height".into());
    }
    let expected = FiContextAssertionExpectation {
        network_id: network,
        chain_id: text(pins, "chainId", 1024)?,
        checkpoint_sha256: raw32(pins, "checkpointSha256")?,
        checkpoint_height: height,
        checkpoint_context_id: raw32(pins, "checkpointContextId")?,
        asset_owner: &owner,
        asset_incarnation: AxtAssetIncarnationV1::try_from_bytes(raw32(pins, "assetIncarnation")?)
            .map_err(|e| e.to_string())?,
        uid: raw32(pins, "uid")?,
        target: &expected_target,
        runtime_manifest_sha256: raw32(pins, "runtimeManifestSha256")?,
        owner_key_identity: text(pins, "ownerKeyIdentity", 256)?,
        fi_participant: text(pins, "fiParticipant", 256)?,
        wallet_scope_canonical: text(pins, "walletScopeCanonical", 16384)?.as_bytes(),
    };
    let prefix = AccountAddress::i105_discriminant(text(pins, "walletAccountId", 1024)?)
        .map_err(|e| e.to_string())?;
    body(&expected, prefix)
}

pub(crate) fn verify_fi_context_json(
    capsule: &[u8],
    original: &[u8],
    checkpoint: &[u8],
    trust: &[u8],
) -> Result<Vec<u8>, String> {
    with_fi_context_trust(original, trust, |expected, prefix| {
        encode_verified_fi_context(
            verify_fi_context_assertion_v1(capsule, original, checkpoint, expected)?,
            prefix,
        )
    })
}

pub(crate) fn encode_verified_fi_context(
    verified: VerifiedFiContextAssertionV1,
    prefix: u16,
) -> Result<Vec<u8>, String> {
    let mut snapshot = json::to_value(&verified.snapshot).map_err(|e| e.to_string())?;
    display_accounts(&mut snapshot, prefix)?;
    let snapshot_bytes = json::to_vec(&snapshot).map_err(|e| e.to_string())?;
    let result=json::to_vec(&norito::json!({"schema":"iroha.fi-context-assertion.verified.v1",
        "requestSha256":(hex::encode(verified.request_sha256)),"blockHash":(hex::encode(verified.block_hash)),
        "blockHeight":(verified.block_height.to_string()),
        "blockCreationTimeMs":(verified.block_creation_time_ms.to_string()),
        "snapshotJsonBase64":(base64::engine::general_purpose::STANDARD.encode(snapshot_bytes))})).map_err(|e|e.to_string())?;
    if result.len() > MAX_OUTPUT_BYTES {
        return Err("verified FI projection exceeds bound".into());
    }
    Ok(result)
}

#[cfg(test)]
mod tests;

/// Four input buffer pairs: canonical capsule, exact retained request, local
/// canonical checkpoint, independently admitted canonical trust JSON. Trust JSON
/// schema is closed above; checkpointHeight is canonical decimal text, hashes
/// lowercase raw32 hex. This operation performs no HTTP or wallet signing.
///
/// # Safety
/// Input buffers must remain readable for their declared lengths. Output slots
/// must be writable and disjoint from each other and every input. Free output
/// using connect_norito_free. All outputs are cleared on failure.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn connect_norito_verify_fi_context_assertion_v1(
    capsule_ptr: *const c_uchar,
    capsule_len: c_ulong,
    original_ptr: *const c_uchar,
    original_len: c_ulong,
    checkpoint_ptr: *const c_uchar,
    checkpoint_len: c_ulong,
    trust_ptr: *const c_uchar,
    trust_len: c_ulong,
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulong,
) -> c_int {
    super::clear_bridge_output(out_ptr, out_len);
    let result = std::panic::catch_unwind(|| {
        if capsule_ptr.is_null()
            || original_ptr.is_null()
            || checkpoint_ptr.is_null()
            || trust_ptr.is_null()
            || out_ptr.is_null()
            || out_len.is_null()
        {
            return Err("null FI verifier argument".to_owned());
        }
        let bound = |length: c_ulong, max: usize| -> Result<usize, String> {
            let length = usize::try_from(length).map_err(|_| "FI verifier length overflow")?;
            if length == 0 || length > max {
                return Err("FI verifier input exceeds bound".into());
            }
            Ok(length)
        };
        let capsule_len = bound(capsule_len, 512 * 1024)?;
        let original_len = bound(original_len, 64 * 1024)?;
        let checkpoint_len = bound(checkpoint_len, MAX_FINALITY_CHECKPOINT_BYTES)?;
        let trust_len = bound(trust_len, MAX_TRUST_BYTES)?;
        verify_fi_context_json(
            unsafe { slice::from_raw_parts(capsule_ptr, capsule_len) },
            unsafe { slice::from_raw_parts(original_ptr, original_len) },
            unsafe { slice::from_raw_parts(checkpoint_ptr, checkpoint_len) },
            unsafe { slice::from_raw_parts(trust_ptr, trust_len) },
        )
    });
    let Ok(Ok(bytes)) = result else {
        return ERR_FI_CONTEXT;
    };
    match unsafe { super::write_bytes(out_ptr, out_len, &bytes) } {
        Ok(()) => 0,
        Err(_) => ERR_FI_CONTEXT,
    }
}
