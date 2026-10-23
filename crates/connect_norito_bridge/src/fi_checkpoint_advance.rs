//! Historical Global checkpoint advancement using the existing native page verifier.
//! No transport, persistence, current-state authority or FI request rewriting occurs here.

use iroha_crypto::sha256;
use iroha_data_model::{
    NetworkId,
    block::consensus::SumeragiRootScope,
    sumeragi_finality::{
        MAX_FINALITY_CHECKPOINT_BYTES, SumeragiFinalityCheckpoint, SumeragiFinalityProof,
        verify_checkpoint_page,
    },
};
use libc::{c_int, c_uchar, c_ulong};
use std::{ptr, slice, str};

const ERR_FI_CHECKPOINT_ADVANCE: c_int = -512;
const MAX_PROOFS: usize = 4096;
const MAX_PROOF_BYTES: usize = 16 * 1024 * 1024;
const MAX_METADATA_BYTES: usize = 4096;

pub(crate) struct VerifiedFiCheckpointAdvance {
    pub checkpoint: Vec<u8>,
    pub metadata: Vec<u8>,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn advance_fi_checkpoint(
    checkpoint_bytes: &[u8],
    proof_wires: &[&[u8]],
    expected_network: NetworkId,
    expected_chain: &str,
    expected_sha256: [u8; 32],
    expected_height: u64,
    expected_context: [u8; 32],
) -> Result<VerifiedFiCheckpointAdvance, String> {
    if !(2..=MAX_PROOFS).contains(&proof_wires.len()) {
        return Err("checkpoint advance requires a bounded page containing a successor".into());
    }
    let mut total = 0_usize;
    for wire in proof_wires {
        total = total
            .checked_add(wire.len())
            .ok_or("checkpoint page byte count overflow")?;
        if wire.is_empty() || total > MAX_PROOF_BYTES {
            return Err("canonical proof page exceeds the existing 16 MiB limit".into());
        }
    }
    if checkpoint_bytes.is_empty() || checkpoint_bytes.len() > MAX_FINALITY_CHECKPOINT_BYTES {
        return Err("selected checkpoint exceeds bound".into());
    }
    let input_bytes = checkpoint_bytes
        .len()
        .checked_add(total)
        .ok_or("checkpoint page input overflow")?;
    norito::core::with_decode_limits_scope(norito::canonical_decode_limits(input_bytes), || {
        // Authenticates the original checkpoint against all independently retained pins,
        // including the exact raw digest, native Global root, height and context.
        let prior = super::fi_checkpoint_selection::verify_fi_checkpoint_selection(
            checkpoint_bytes,
            expected_network,
            expected_chain,
            expected_sha256,
            expected_height,
            expected_context,
        )?;
        let checkpoint = SumeragiFinalityCheckpoint::decode_canonical(checkpoint_bytes)
            .map_err(|error| error.to_string())?;
        let mut proofs = Vec::new();
        proofs
            .try_reserve_exact(proof_wires.len())
            .map_err(|error| error.to_string())?;
        for wire in proof_wires {
            let proof: SumeragiFinalityProof = norito::decode_canonical_for_admission(
                wire,
                norito::canonical_decode_limits(wire.len()),
            )
            .map_err(|error| error.to_string())?;
            proofs.push(proof);
        }
        // This is the sole page-verification algorithm. It requires the first proof
        // to authenticate the exact prior decision and all successors to be consecutive.
        let page = verify_checkpoint_page(
            expected_network,
            &checkpoint,
            &proofs,
            MAX_PROOFS,
            MAX_PROOF_BYTES,
        )
        .map_err(|error| error.to_string())?;
        let tip = page.tip();
        if tip.root_scope() != SumeragiRootScope::Global
            || tip.height() <= prior.height
            || tip.height() == u64::MAX
        {
            return Err(
                "checkpoint page does not advance the independently selected Global tip".into(),
            );
        }
        let promoted = page
            .checkpoint()
            .encode_canonical()
            .map_err(|error| error.to_string())?;
        if promoted.is_empty() || promoted.len() > MAX_FINALITY_CHECKPOINT_BYTES {
            return Err("promoted checkpoint exceeds existing native bound".into());
        }
        let metadata = norito::json::to_json_bounded(&norito::json!({
            "schema":"iroha.fi-checkpoint-advance.verified.v1",
            "networkId":(expected_network.to_string()), "chainId":expected_chain,
            "anchorHeight":(prior.height.to_string()), "height":(tip.height().to_string()),
            "proofCount":(proofs.len().to_string()), "checkpointSha256":(hex::encode(sha256(&promoted))),
            "contextId":(hex::encode(tip.context_id().as_ref())),
            "blockHash":(hex::encode(tip.header().hash().as_ref()))
        }), MAX_METADATA_BYTES).map_err(|error| error.to_string())?.into_bytes();
        Ok(VerifiedFiCheckpointAdvance {
            checkpoint: promoted,
            metadata,
        })
    })
}

struct OwnedOutput {
    pointer: *mut c_uchar,
    length: c_ulong,
}
impl OwnedOutput {
    fn new(bytes: &[u8]) -> Result<Self, String> {
        let mut value = Self {
            pointer: ptr::null_mut(),
            length: 0,
        };
        unsafe { super::write_bytes(&mut value.pointer, &mut value.length, bytes) }
            .map_err(|_| "checkpoint advance output allocation failed".to_owned())?;
        Ok(value)
    }
}
impl Drop for OwnedOutput {
    fn drop(&mut self) {
        crate::connect_norito_free(self.pointer);
    }
}

/// Advance the selected checkpoint using exact original canonical proof frames.
///
/// Nineteen arguments: checkpoint pair; proof pointer array/length array/count;
/// network pair; chain pair; raw SHA32 pair; decimal height pair; context32 pair;
/// checkpoint output pair; metadata output pair. Metadata has the nine string keys
/// documented by `advance_fi_checkpoint`. Both outputs use `connect_norito_free`.
///
/// # Safety
/// Nonempty input buffers and pointer/length arrays must be readable and aligned
/// for their declared sizes throughout this call. All four writable output slots
/// must be nonnull and disjoint from each other and every input. No input is retained.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn connect_norito_advance_fi_checkpoint_v1(
    checkpoint_ptr: *const c_uchar,
    checkpoint_len: c_ulong,
    proof_ptrs: *const *const c_uchar,
    proof_lengths: *const c_ulong,
    proof_count: c_ulong,
    network_ptr: *const c_uchar,
    network_len: c_ulong,
    chain_ptr: *const c_uchar,
    chain_len: c_ulong,
    sha_ptr: *const c_uchar,
    sha_len: c_ulong,
    height_ptr: *const c_uchar,
    height_len: c_ulong,
    context_ptr: *const c_uchar,
    context_len: c_ulong,
    out_checkpoint_ptr: *mut *mut c_uchar,
    out_checkpoint_len: *mut c_ulong,
    out_metadata_ptr: *mut *mut c_uchar,
    out_metadata_len: *mut c_ulong,
) -> c_int {
    super::clear_bridge_output(out_checkpoint_ptr, out_checkpoint_len);
    super::clear_bridge_output(out_metadata_ptr, out_metadata_len);
    let result = std::panic::catch_unwind(|| {
        if checkpoint_ptr.is_null()
            || proof_ptrs.is_null()
            || proof_lengths.is_null()
            || network_ptr.is_null()
            || chain_ptr.is_null()
            || sha_ptr.is_null()
            || height_ptr.is_null()
            || context_ptr.is_null()
            || out_checkpoint_ptr.is_null()
            || out_checkpoint_len.is_null()
            || out_metadata_ptr.is_null()
            || out_metadata_len.is_null()
        {
            return Err("null checkpoint advance argument".to_owned());
        }
        let bounded = |length: c_ulong, max: usize| -> Result<usize, String> {
            let length = usize::try_from(length).map_err(|_| "checkpoint advance size overflow")?;
            if length == 0 || length > max {
                return Err("checkpoint advance size exceeds bound".into());
            }
            Ok(length)
        };
        let count = bounded(proof_count, MAX_PROOFS)?;
        if count < 2 || sha_len != 32 || context_len != 32 {
            return Err("invalid checkpoint advance selection size".into());
        }
        let checkpoint_len = bounded(checkpoint_len, MAX_FINALITY_CHECKPOINT_BYTES)?;
        let network_len = bounded(network_len, 74)?;
        let chain_len = bounded(chain_len, 1024)?;
        let height_len = bounded(height_len, 20)?;
        let pointers = unsafe { slice::from_raw_parts(proof_ptrs, count) };
        let lengths = unsafe { slice::from_raw_parts(proof_lengths, count) };
        let mut wires = Vec::new();
        wires
            .try_reserve_exact(count)
            .map_err(|error| error.to_string())?;
        let mut total = 0_usize;
        for (pointer, length) in pointers.iter().zip(lengths) {
            if pointer.is_null() {
                return Err("null canonical proof frame".into());
            }
            let length = bounded(*length, MAX_PROOF_BYTES)?;
            total = total
                .checked_add(length)
                .ok_or("proof page byte count overflow")?;
            if total > MAX_PROOF_BYTES {
                return Err("proof page exceeds 16 MiB".into());
            }
            wires.push(unsafe { slice::from_raw_parts(*pointer, length) });
        }
        let text = |pointer, length| {
            str::from_utf8(unsafe { slice::from_raw_parts(pointer, length) })
                .map_err(|_| "checkpoint selector is not UTF-8".to_owned())
        };
        let network = text(network_ptr, network_len)?
            .parse::<NetworkId>()
            .map_err(|error| error.to_string())?;
        let chain = text(chain_ptr, chain_len)?;
        let height_text = text(height_ptr, height_len)?;
        let height = height_text
            .parse::<u64>()
            .map_err(|error| error.to_string())?;
        if height.to_string() != height_text {
            return Err("noncanonical checkpoint height".into());
        }
        let digest = unsafe { slice::from_raw_parts(sha_ptr, 32) }
            .try_into()
            .map_err(|_| "invalid checkpoint SHA")?;
        let context = unsafe { slice::from_raw_parts(context_ptr, 32) }
            .try_into()
            .map_err(|_| "invalid checkpoint context")?;
        let output = advance_fi_checkpoint(
            unsafe { slice::from_raw_parts(checkpoint_ptr, checkpoint_len) },
            &wires,
            network,
            chain,
            digest,
            height,
            context,
        )?;
        Ok::<_, String>((
            OwnedOutput::new(&output.checkpoint)?,
            OwnedOutput::new(&output.metadata)?,
        ))
    });
    let Ok(Ok((mut checkpoint, mut metadata))) = result else {
        return ERR_FI_CHECKPOINT_ADVANCE;
    };
    unsafe {
        *out_checkpoint_ptr = checkpoint.pointer;
        *out_checkpoint_len = checkpoint.length;
        *out_metadata_ptr = metadata.pointer;
        *out_metadata_len = metadata.length;
    }
    checkpoint.pointer = ptr::null_mut();
    metadata.pointer = ptr::null_mut();
    0
}

#[cfg(test)]
#[path = "fi_checkpoint_advance_tests.rs"]
mod tests;
