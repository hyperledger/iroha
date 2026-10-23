//! Admit one exact signed assertion without an execution claim, then authenticate
//! its successful inclusion from a separately admitted operation-branch cursor.
//! Original-floor provenance and branch generations belong to protected custody;
//! neither a response checkpoint nor a JSON verified flag is an admission input.
use super::{
    fi_checkpoint_selection::verify_fi_checkpoint_selection,
    fi_context_bridge::{encode_verified_fi_context, raw32, text, with_fi_context_trust},
    fi_context_verification::{
        FiContextAssertionExpectation, VerifiedFiContextAssertionV1, bind_assertion,
        bind_assertion_original, bind_request,
    },
};
use iroha_crypto::sha256;
use iroha_data_model::{
    asset::{
        fi_evidence::AssetFiContextAssertionCapsuleV1,
        fi_request::{NormalizedAssetFiContextRequestV1, normalize_asset_fi_context_request_v1},
    },
    sumeragi_finality::MAX_FINALITY_CHECKPOINT_BYTES,
    transaction::SignedTransaction,
};
use libc::{c_int, c_uchar, c_ulong};
use norito::json::{self, Value};
use std::slice;

const MAX_SIGNED_ORIGINAL_BYTES: usize = 64 * 1024;
const MAX_REQUEST_BYTES: usize = 64 * 1024;
const MAX_CAPSULE_BYTES: usize = 512 * 1024;
const MAX_TRUST_BYTES: usize = 32 * 1024;
const MAX_CONTINUATION_TRUST_BYTES: usize = 36 * 1024;
const ERR_FI_ASSERTION_ORIGINAL: c_int = -513;
const ERR_FI_CONTEXT_CONTINUATION: c_int = -514;

/// Only signed-original admission facts. There is no snapshot, success or freshness field.
pub(crate) struct AdmittedFiAssertionOriginal {
    pub request_sha256: [u8; 32],
    pub assertion_entrypoint_hash: [u8; 32],
    pub assertion_wire_sha256: [u8; 32],
    pub original_checkpoint_height: u64,
    pub original_checkpoint_block_hash: [u8; 32],
}
impl AdmittedFiAssertionOriginal {
    fn to_json(&self) -> Result<Vec<u8>, String> {
        json::to_json_bounded(
            &norito::json!({
                "schema":"iroha.fi-assertion-original.admitted.v1",
                "requestSha256":(hex::encode(self.request_sha256)),
                "assertionEntrypointHash":(hex::encode(self.assertion_entrypoint_hash)),
                "assertionWireSha256":(hex::encode(self.assertion_wire_sha256)),
                "originalCheckpointHeight":(self.original_checkpoint_height.to_string()),
                "originalCheckpointBlockHash":(hex::encode(self.original_checkpoint_block_hash))
            }),
            2048,
        )
        .map(String::into_bytes)
        .map_err(|error| error.to_string())
    }
}

fn admit_original(
    signed_wire: &[u8],
    original_request: &[u8],
    original_checkpoint: &[u8],
    expected: &FiContextAssertionExpectation<'_>,
) -> Result<
    (
        AdmittedFiAssertionOriginal,
        SignedTransaction,
        NormalizedAssetFiContextRequestV1,
    ),
    String,
> {
    if signed_wire.is_empty() || signed_wire.len() > MAX_SIGNED_ORIGINAL_BYTES {
        return Err("FI signed original exceeds the status contract bound".into());
    }
    let request = normalize_asset_fi_context_request_v1(original_request)?;
    bind_request(&request, expected)?;
    // Mandatory even when a later cursor is available: it authenticates the floor
    // selected by the retained original, never a newer current runtime checkpoint.
    let floor = verify_fi_checkpoint_selection(
        original_checkpoint,
        expected.network_id,
        expected.chain_id,
        expected.checkpoint_sha256,
        expected.checkpoint_height,
        expected.checkpoint_context_id,
    )?;
    let transaction = super::decode_signed_transaction(signed_wire)
        .map_err(|error| format!("invalid original FI signed wire: {error}"))?;
    bind_assertion_original(&transaction, &request, expected, floor.block_hash)?;
    let hash = transaction
        .try_hash_as_entrypoint()
        .map_err(|error| error.to_string())?;
    Ok((
        AdmittedFiAssertionOriginal {
            request_sha256: request.original_sha256,
            assertion_entrypoint_hash: *hash.as_ref(),
            assertion_wire_sha256: sha256(signed_wire),
            original_checkpoint_height: floor.height,
            original_checkpoint_block_hash: floor.block_hash,
        },
        transaction,
        request,
    ))
}

pub(crate) fn admit_fi_assertion_original_json(
    signed_wire: &[u8],
    original_request: &[u8],
    original_checkpoint: &[u8],
    trust: &[u8],
) -> Result<Vec<u8>, String> {
    with_fi_context_trust(original_request, trust, |expected, _| {
        admit_original(signed_wire, original_request, original_checkpoint, expected)?
            .0
            .to_json()
    })
}

/// Explicitly independent local branch pins. The durable owner must have verified
/// consecutive pages from the original floor and rechecked branch generation at
/// adoption. Importing a checkpoint against its own response digest is prohibited.
pub(crate) struct FiContinuationCursor {
    pub sha256: [u8; 32],
    pub height: u64,
    pub context_id: [u8; 32],
    pub block_hash: [u8; 32],
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_fi_context_continuation(
    capsule_bytes: &[u8],
    original_request: &[u8],
    retained_signed_wire: &[u8],
    original_checkpoint: &[u8],
    cursor_checkpoint: &[u8],
    expected: &FiContextAssertionExpectation<'_>,
    cursor: &FiContinuationCursor,
) -> Result<VerifiedFiContextAssertionV1, String> {
    if capsule_bytes.is_empty() || capsule_bytes.len() > MAX_CAPSULE_BYTES {
        return Err("FI continuation capsule exceeds bound".into());
    }
    let (admitted, transaction, request) = admit_original(
        retained_signed_wire,
        original_request,
        original_checkpoint,
        expected,
    )?;
    let selected_cursor = verify_fi_checkpoint_selection(
        cursor_checkpoint,
        expected.network_id,
        expected.chain_id,
        cursor.sha256,
        cursor.height,
        cursor.context_id,
    )?;
    if selected_cursor.height < admitted.original_checkpoint_height
        || selected_cursor.block_hash != cursor.block_hash
        || (selected_cursor.height == admitted.original_checkpoint_height
            && (selected_cursor.block_hash != admitted.original_checkpoint_block_hash
                || cursor.context_id != expected.checkpoint_context_id))
    {
        return Err("FI continuation cursor differs from the admitted operation branch".into());
    }
    let capsule = AssetFiContextAssertionCapsuleV1::decode_canonical(capsule_bytes)?;
    if capsule.assertion_signed_transaction != retained_signed_wire {
        return Err("FI continuation substituted the retained signed assertion".into());
    }
    // This is the complete original snapshot binding, including the expected
    // context hash that candidate admission alone deliberately cannot establish.
    bind_assertion(
        &transaction,
        &capsule.snapshot,
        &request,
        expected,
        admitted.original_checkpoint_block_hash,
    )?;
    let chain_json =
        json::to_vec(&capsule.finality_proof_chain).map_err(|error| error.to_string())?;
    let committed =
        super::committed_transaction_inclusion::verify_exact_successful_committed_transaction(
            &capsule.committed_transaction_response,
            &chain_json,
            expected.network_id,
            expected.chain_id,
            cursor_checkpoint,
            retained_signed_wire,
        )?;
    if !committed.global_root
        || !committed.result_ok
        || committed.block_height <= admitted.original_checkpoint_height
        || committed.block_height < selected_cursor.height
        || committed.block_creation_time_ms == 0
    {
        return Err(
            "FI continuation needs exact successful Global execution after ORIGINAL floor".into(),
        );
    }
    Ok(VerifiedFiContextAssertionV1 {
        snapshot: capsule.snapshot,
        request_sha256: request.original_sha256,
        block_hash: committed.block_hash,
        block_height: committed.block_height,
        block_creation_time_ms: committed.block_creation_time_ms,
    })
}

pub(crate) fn verify_fi_context_continuation_json(
    capsule: &[u8],
    request: &[u8],
    retained_wire: &[u8],
    original_checkpoint: &[u8],
    cursor_checkpoint: &[u8],
    trust: &[u8],
) -> Result<Vec<u8>, String> {
    if trust.is_empty() || trust.len() > MAX_CONTINUATION_TRUST_BYTES {
        return Err("FI continuation local trust exceeds bound".into());
    }
    let value = json::from_slice_value(trust).map_err(|error| error.to_string())?;
    if json::to_vec(&value).map_err(|error| error.to_string())? != trust {
        return Err("FI continuation local trust must be canonical JSON".into());
    }
    let fields = value
        .as_object()
        .ok_or("FI continuation trust must be an object")?;
    if fields.len() != 3
        || text(fields, "schema", 64)? != "iroha.fi-context-continuation-trust.v1"
        || !fields.contains_key("original")
        || !fields.contains_key("cursor")
    {
        return Err("unknown or missing FI continuation trust fields".into());
    }
    let original = json::to_vec(fields.get("original").ok_or("missing original trust")?)
        .map_err(|error| error.to_string())?;
    let cursor = fields
        .get("cursor")
        .and_then(Value::as_object)
        .ok_or("missing cursor selection")?;
    const KEYS: &[&str] = &[
        "checkpointSha256",
        "checkpointHeight",
        "checkpointContextId",
        "checkpointBlockHash",
    ];
    if cursor.len() != KEYS.len() || KEYS.iter().any(|key| !cursor.contains_key(*key)) {
        return Err("unknown or missing FI continuation cursor selectors".into());
    }
    let height_text = text(cursor, "checkpointHeight", 20)?;
    let height = height_text
        .parse::<u64>()
        .map_err(|error| error.to_string())?;
    if height == 0 || height == u64::MAX || height.to_string() != height_text {
        return Err("FI cursor height is not canonical usable u64".into());
    }
    let cursor = FiContinuationCursor {
        sha256: raw32(cursor, "checkpointSha256")?,
        height,
        context_id: raw32(cursor, "checkpointContextId")?,
        block_hash: raw32(cursor, "checkpointBlockHash")?,
    };
    with_fi_context_trust(request, &original, |expected, prefix| {
        encode_verified_fi_context(
            verify_fi_context_continuation(
                capsule,
                request,
                retained_wire,
                original_checkpoint,
                cursor_checkpoint,
                expected,
                &cursor,
            )?,
            prefix,
        )
    })
}

unsafe fn bounded<'a>(
    pointer: *const c_uchar,
    length: c_ulong,
    maximum: usize,
) -> Result<&'a [u8], String> {
    let length = usize::try_from(length).map_err(|_| "FI continuation size overflow")?;
    if pointer.is_null() || length == 0 || length > maximum {
        return Err("FI continuation argument is null or exceeds bound".into());
    }
    Ok(unsafe { slice::from_raw_parts(pointer, length) })
}

/// Admit an exact signed candidate without authenticating snapshot, execution or freshness.
///
/// # Safety
/// Four input buffers must be readable at their stated lengths; writable output
/// slots must be disjoint from all inputs and each other. Free using connect_norito_free.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn connect_norito_admit_fi_assertion_original_v1(
    wire: *const c_uchar,
    wire_len: c_ulong,
    request: *const c_uchar,
    request_len: c_ulong,
    checkpoint: *const c_uchar,
    checkpoint_len: c_ulong,
    trust: *const c_uchar,
    trust_len: c_ulong,
    out: *mut *mut c_uchar,
    out_len: *mut c_ulong,
) -> c_int {
    super::clear_bridge_output(out, out_len);
    let result = std::panic::catch_unwind(|| {
        if out.is_null() || out_len.is_null() {
            return Err("null FI admission output".into());
        }
        unsafe {
            admit_fi_assertion_original_json(
                bounded(wire, wire_len, MAX_SIGNED_ORIGINAL_BYTES)?,
                bounded(request, request_len, MAX_REQUEST_BYTES)?,
                bounded(checkpoint, checkpoint_len, MAX_FINALITY_CHECKPOINT_BYTES)?,
                bounded(trust, trust_len, MAX_TRUST_BYTES)?,
            )
        }
    });
    let Ok(Ok(bytes)) = result else {
        return ERR_FI_ASSERTION_ORIGINAL;
    };
    match unsafe { super::write_bytes(out, out_len, &bytes) } {
        Ok(()) => 0,
        Err(_) => ERR_FI_ASSERTION_ORIGINAL,
    }
}

/// Verify the exact retained assertion from an independently admitted branch cursor.
/// Original floor and cursor are distinct local inputs; neither is response-selected.
///
/// # Safety
/// Six input buffers must be readable at their stated lengths; writable output
/// slots must be disjoint from all inputs and each other. Free using connect_norito_free.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn connect_norito_verify_fi_context_continuation_v1(
    capsule: *const c_uchar,
    capsule_len: c_ulong,
    request: *const c_uchar,
    request_len: c_ulong,
    wire: *const c_uchar,
    wire_len: c_ulong,
    floor: *const c_uchar,
    floor_len: c_ulong,
    cursor: *const c_uchar,
    cursor_len: c_ulong,
    trust: *const c_uchar,
    trust_len: c_ulong,
    out: *mut *mut c_uchar,
    out_len: *mut c_ulong,
) -> c_int {
    super::clear_bridge_output(out, out_len);
    let result = std::panic::catch_unwind(|| {
        if out.is_null() || out_len.is_null() {
            return Err("null FI continuation output".into());
        }
        unsafe {
            verify_fi_context_continuation_json(
                bounded(capsule, capsule_len, MAX_CAPSULE_BYTES)?,
                bounded(request, request_len, MAX_REQUEST_BYTES)?,
                bounded(wire, wire_len, MAX_SIGNED_ORIGINAL_BYTES)?,
                bounded(floor, floor_len, MAX_FINALITY_CHECKPOINT_BYTES)?,
                bounded(cursor, cursor_len, MAX_FINALITY_CHECKPOINT_BYTES)?,
                bounded(trust, trust_len, MAX_CONTINUATION_TRUST_BYTES)?,
            )
        }
    });
    let Ok(Ok(bytes)) = result else {
        return ERR_FI_CONTEXT_CONTINUATION;
    };
    match unsafe { super::write_bytes(out, out_len, &bytes) } {
        Ok(()) => 0,
        Err(_) => ERR_FI_CONTEXT_CONTINUATION,
    }
}

#[cfg(test)]
#[path = "fi_context_continuation_tests.rs"]
mod tests;
