//! Authenticate local FI checkpoint bytes independently selected by the signed runtime.
//! This authenticates a historical Global tip, never freshness, current World or physical routing.

use std::{slice, str};

use iroha_data_model::{
    NetworkId,
    block::consensus::SumeragiRootScope,
    sumeragi_finality::{
        MAX_FINALITY_CHECKPOINT_BYTES, SumeragiFinalityCheckpoint, SumeragiFinalityVerifier,
    },
};
use libc::{c_int, c_uchar, c_ulong};
use iroha_crypto::sha256;

const ERR_FI_CHECKPOINT: c_int = -510;

pub(crate) struct VerifiedFiCheckpointSelection {
    pub height: u64,
    pub context_id: [u8; 32],
    pub block_hash: [u8; 32],
}

impl VerifiedFiCheckpointSelection {
    pub(crate) fn to_json(&self) -> Vec<u8> {
        format!(
            "{{\"height\":\"{}\",\"context_id\":\"{}\",\"block_hash\":\"{}\"}}",
            self.height,
            hex::encode(self.context_id),
            hex::encode(self.block_hash)
        )
        .into_bytes()
    }
}

pub(crate) fn verify_fi_checkpoint_selection(
    checkpoint_bytes: &[u8],
    expected_network_id: NetworkId,
    expected_chain: &str,
    expected_sha256: [u8; 32],
    expected_height: u64,
    expected_context_id: [u8; 32],
) -> Result<VerifiedFiCheckpointSelection, String> {
    if checkpoint_bytes.is_empty()
        || checkpoint_bytes.len() > MAX_FINALITY_CHECKPOINT_BYTES
        || expected_chain.is_empty()
        || expected_chain.len() > 1024
        || expected_chain.trim() != expected_chain
        || expected_chain.chars().any(char::is_control)
        || expected_sha256 == [0; 32]
        || expected_context_id == [0; 32]
        || expected_height == 0
        || expected_height == u64::MAX
        || <[u8; 32]>::from(sha256(checkpoint_bytes)) != expected_sha256
    {
        return Err("checkpoint differs from independently signed selection".into());
    }
    let checkpoint = SumeragiFinalityCheckpoint::decode_canonical(checkpoint_bytes)
        .map_err(|error| format!("invalid canonical checkpoint: {error}"))?;
    let (_, tip) = SumeragiFinalityVerifier::from_trusted_checkpoint_with_tip(
        &checkpoint,
        &expected_network_id,
        expected_chain,
    )
    .map_err(|error| format!("checkpoint authentication failed: {error}"))?;
    if tip.root_scope() != SumeragiRootScope::Global
        || tip.height() != expected_height
        || tip.context_id().as_ref() != &expected_context_id
    {
        return Err("checkpoint tip differs from selected Global context".into());
    }
    Ok(VerifiedFiCheckpointSelection {
        height: tip.height(),
        context_id: *tip.context_id().as_ref(),
        block_hash: *tip.header().hash().as_ref(),
    })
}

/// Six input buffers: canonical checkpoint, checked NetworkId UTF-8 literal,
/// chain UTF-8, raw SHA256, canonical unsigned decimal height UTF-8, raw context ID.
/// All selectors MUST come from independently admitted local runtime state.
///
/// # Safety
/// Nonempty inputs reference readable storage of the declared lengths. Output
/// pointer/length references are writable, disjoint from each other and all inputs.
/// Release the returned buffer with `connect_norito_free`. Outputs are cleared on failure.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn connect_norito_verify_fi_checkpoint_selection_v1(
    checkpoint_ptr: *const c_uchar,
    checkpoint_len: c_ulong,
    network_ptr: *const c_uchar,
    network_len: c_ulong,
    chain_ptr: *const c_uchar,
    chain_len: c_ulong,
    sha256_ptr: *const c_uchar,
    sha256_len: c_ulong,
    height_ptr: *const c_uchar,
    height_len: c_ulong,
    context_ptr: *const c_uchar,
    context_len: c_ulong,
    out_ptr: *mut *mut c_uchar,
    out_len: *mut c_ulong,
) -> c_int {
    super::clear_bridge_output(out_ptr, out_len);
    let result = std::panic::catch_unwind(|| {
        if checkpoint_ptr.is_null()
            || network_ptr.is_null()
            || chain_ptr.is_null()
            || sha256_ptr.is_null()
            || height_ptr.is_null()
            || context_ptr.is_null()
            || out_ptr.is_null()
            || out_len.is_null()
        {
            return Err("null checkpoint argument".to_owned());
        }
        let bounded = |length: c_ulong, maximum: usize| -> Result<usize, String> {
            let length =
                usize::try_from(length).map_err(|_| "length exceeds platform size".to_owned())?;
            if length == 0 || length > maximum {
                return Err("checkpoint argument exceeds bound".into());
            }
            Ok(length)
        };
        let checkpoint_len = bounded(checkpoint_len, MAX_FINALITY_CHECKPOINT_BYTES)?;
        let network_len = bounded(network_len, 74)?;
        let chain_len = bounded(chain_len, 1024)?;
        let height_len = bounded(height_len, 20)?;
        if sha256_len != 32 || context_len != 32 {
            return Err("checkpoint pin must be 32 bytes".into());
        }
        let network = str::from_utf8(unsafe { slice::from_raw_parts(network_ptr, network_len) })
            .map_err(|error| error.to_string())?
            .parse::<NetworkId>()
            .map_err(|error| error.to_string())?;
        let chain = str::from_utf8(unsafe { slice::from_raw_parts(chain_ptr, chain_len) })
            .map_err(|error| error.to_string())?;
        let height_text = str::from_utf8(unsafe { slice::from_raw_parts(height_ptr, height_len) })
            .map_err(|error| error.to_string())?;
        let height = height_text
            .parse::<u64>()
            .map_err(|error| error.to_string())?;
        if height.to_string() != height_text {
            return Err("noncanonical checkpoint height".into());
        }
        verify_fi_checkpoint_selection(
            unsafe { slice::from_raw_parts(checkpoint_ptr, checkpoint_len) },
            network,
            chain,
            unsafe { slice::from_raw_parts(sha256_ptr, 32) }
                .try_into()
                .expect("fixed SHA size"),
            height,
            unsafe { slice::from_raw_parts(context_ptr, 32) }
                .try_into()
                .expect("fixed context size"),
        )
    });
    let Ok(Ok(verified)) = result else {
        return ERR_FI_CHECKPOINT;
    };
    match unsafe { super::write_bytes(out_ptr, out_len, &verified.to_json()) } {
        Ok(()) => 0,
        Err(_) => ERR_FI_CHECKPOINT,
    }
}

#[cfg(test)]
mod tests;
