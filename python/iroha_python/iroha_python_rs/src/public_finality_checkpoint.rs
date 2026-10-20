//! Public historical finality from an independently selected exact genesis.
//!
//! Unlike installed/private authoring admission, the unchanged selected public
//! genesis may carry execution results and a certificate. Those fields confer no
//! execution authority: only a contiguous native proof chain including a genuine
//! successor can produce the returned checkpoint. No World/current-cut grant.
use iroha_crypto::HashOf;
use iroha_data_model::{
    NetworkId,
    block::{BlockHeader, consensus::SumeragiRootScope, decode_framed_signed_block},
    sumeragi_finality::{
        FinalityReadError, FinalityValidator, GenesisReadError, SumeragiFinalityProof,
        SumeragiFinalityVerifier, authenticated_genesis,
    },
};
use norito::json;
use pyo3::{
    exceptions::PyException,
    prelude::*,
    types::{PyBytes, PyTuple},
};
use sha2::{Digest as _, Sha256};

const MAX_GENESIS: usize = 8 * 1024 * 1024;
const MAX_CHAIN: usize = 512;
// Match the existing Python committed-inclusion page's closed count/byte limits.
const MAX_PROOFS: usize = 4096;
const MAX_PROOF_BYTES: usize = 16 * 1024 * 1024;
const MAX_TIP_JSON: usize = 16 * 1024 * 1024;

pyo3::create_exception!(
    _crypto,
    PublicFinalityReadError,
    PyException,
    "Public historical finality refusal with native kind and phase diagnostics."
);

#[derive(Debug)]
enum Failure {
    Input(&'static str),
    Native(&'static str, FinalityReadError),
    Json(json::BoundedJsonError),
    Allocation(std::collections::TryReserveError),
    Encoding(String),
}
impl Failure {
    fn into_py(self, py: Python<'_>) -> PyErr {
        // Preserve the signed-body reader's own distinction without declaring an
        // unfinished JSON/resource read cryptographically invalid.
        let source_kind = match &self {
            Self::Native(_, FinalityReadError::Genesis(GenesisReadError::Invalid(_))) => {
                Some("invalid")
            }
            Self::Native(_, FinalityReadError::Genesis(GenesisReadError::Json(error))) => {
                Some(if error.is_decode_resource_limit() {
                    "json_resource"
                } else {
                    "json"
                })
            }
            _ => None,
        };
        let (kind, phase, details) = match self {
            Self::Input(message) => ("input", "admission", message.to_owned()),
            Self::Native(phase, error) => {
                let kind = match &error {
                    FinalityReadError::Invalid(_) => "invalid",
                    FinalityReadError::Genesis(_) => "genesis_read",
                    FinalityReadError::DecodeResource(_) => "decode_resource",
                    FinalityReadError::ScratchLimit(_) => "scratch_limit",
                    FinalityReadError::Allocator(_) => "allocator",
                };
                // Preserve the original native error, including decoder refusal
                // diagnostics. A genesis-read/resource failure is not invalidity.
                (kind, phase, error.to_string())
            }
            Self::Json(error) => ("output_json", "publication", error.to_string()),
            Self::Allocation(error) => ("allocator", "admission", error.to_string()),
            Self::Encoding(error) => ("encoding", "publication", error),
        };
        let error = PublicFinalityReadError::new_err(details);
        if let Err(attribute_error) = error
            .value(py)
            .setattr("kind", kind)
            .and_then(|()| error.value(py).setattr("phase", phase))
            .and_then(|()| error.value(py).setattr("source_kind", source_kind))
        {
            return attribute_error;
        }
        error
    }
}
#[derive(Debug)]
struct Output {
    metadata_json: String,
    checkpoint: Vec<u8>,
    tip_proof_chain_json: String,
}
fn validate_bounds(
    genesis: &[u8],
    proofs: &[&[u8]],
    chain: &str,
    sha: &[u8],
) -> Result<(), Failure> {
    if genesis.is_empty()
        || genesis.len() > MAX_GENESIS
        || chain.is_empty()
        || chain.len() > MAX_CHAIN
        || chain.trim() != chain
        || chain.chars().any(char::is_control)
        || sha.len() != 32
        || sha.iter().all(|b| *b == 0)
        || !(2..=MAX_PROOFS).contains(&proofs.len())
    {
        return Err(Failure::Input(
            "public genesis/pins require bounded exact inputs and at least two proofs",
        ));
    }
    let mut total = 0usize;
    for wire in proofs {
        total = total
            .checked_add(wire.len())
            .ok_or(Failure::Input("proof byte count overflow"))?;
        if wire.is_empty() || total > MAX_PROOF_BYTES {
            return Err(Failure::Input(
                "proof frames must be nonempty and total at most 16 MiB",
            ));
        }
    }
    Ok(())
}
// The native policy bounds outer allocation as well as fields/elements/depth:
// at most 264 MiB + 64 KiB for genesis, 272 MiB + 64 KiB for one proof.
// Nested decodes inherit the stricter enclosing budget. These are per-decode
// ceilings, not a total-process memory bound; finality retains three decisions.
fn decode_proof(wire: &[u8]) -> Result<SumeragiFinalityProof, Failure> {
    norito::decode_canonical_for_admission(wire, norito::canonical_decode_limits(wire.len()))
        .map_err(|e| Failure::Native("proof_decode", e.into()))
}
fn authenticate(
    genesis: &[u8],
    proofs: &[&[u8]],
    network: NetworkId,
    chain: &str,
    sha: &[u8],
) -> Result<Output, Failure> {
    validate_bounds(genesis, proofs, chain, sha)?;
    if Sha256::digest(genesis).as_slice() != sha {
        return Err(Failure::Input(
            "selected genesis differs from independent raw SHA-256",
        ));
    }
    let block = norito::core::with_decode_limits_scope(
        norito::canonical_decode_limits(genesis.len()),
        || decode_framed_signed_block(genesis),
    )
    .map_err(|e| Failure::Native("genesis_decode", e.into()))?;
    if block
        .encode_wire()
        .map_err(|e| Failure::Encoding(e.to_string()))?
        != genesis
        || !block.header().is_genesis()
        || NetworkId::from_genesis_hash(block.hash()) != network
    {
        return Err(Failure::Input(
            "genesis differs from canonical selected network",
        ));
    }
    // This is the native PUBLIC trust flow. Do not strip a certificate or use
    // authenticate_signed_genesis_v1, whose installed-authoring contract differs.
    let authenticated = authenticated_genesis(&block)
        .map_err(|e| Failure::Native("genesis_authentication", e.into()))?;
    let (epoch, scope) = authenticated.into_parts();
    if scope != SumeragiRootScope::Global || epoch.network_id != network {
        return Err(Failure::Input(
            "public finality requires the selected Global genesis",
        ));
    }
    let validators = epoch
        .committee
        .iter()
        .map(|member| FinalityValidator {
            public_key: member.validator.public_key().clone(),
            proof_of_possession: member.proof_of_possession.clone(),
        })
        .collect();
    let mut verifier = SumeragiFinalityVerifier::new(&block, chain, validators)
        .map_err(|e| Failure::Native("verifier_initialization", e))?;
    let mut last = None;
    for wire in proofs {
        let proof = decode_proof(wire)?;
        let verified = verifier
            .verify(&proof)
            .map_err(|e| Failure::Native("proof_verification", e))?;
        verifier.retain_recent_decisions(3);
        last = Some((proof, verified));
    }
    let (tip, verified) = last.ok_or(Failure::Input("missing verified successor"))?;
    if verified.height() < 2 || verified.height() != proofs.len() as u64 {
        return Err(Failure::Input(
            "public finality requires the complete prefix including a successor",
        ));
    }
    let checkpoint = verifier
        .export_checkpoint(&tip)
        .map_err(|e| Failure::Native("checkpoint_export", e))?
        .encode_canonical()
        .map_err(|e| Failure::Native("checkpoint_encoding", e.into()))?;
    // A one-proof page reauthenticates this exact exported checkpoint in the
    // existing committed-inclusion API; it is never an independently chosen root.
    let tip_proof_chain_json =
        json::to_json_bounded(&[tip], MAX_TIP_JSON).map_err(Failure::Json)?;
    let header_hash: HashOf<BlockHeader> = verified.header().hash();
    let metadata_json = json::to_json_bounded(
        &norito::json!({
            "network_id": (network.to_string()), "chain_id": chain,
            "genesis_sha256": (hex::encode(sha)), "root_scope": "Global",
            "height": (verified.height()), "proof_count": (proofs.len() as u64),
            "block_hash": (hex::encode(header_hash.as_ref())),
            "context_id": (hex::encode(verified.context_id().as_ref())),
        }),
        4096,
    )
    .map_err(Failure::Json)?;
    Ok(Output {
        metadata_json,
        checkpoint,
        tip_proof_chain_json,
    })
}

/// Authenticate historical public execution using independently selected exact genesis pins.
/// Returns metadata, immutable checkpoint and canonical one-proof tip JSON only after success.
#[pyfunction]
#[pyo3(signature = (genesis, proof_wires, *, expected_network_id, expected_chain, expected_genesis_sha256))]
fn authenticate_public_finality_checkpoint_v1(
    py: Python<'_>,
    genesis: &Bound<'_, PyBytes>,
    proof_wires: &Bound<'_, PyTuple>,
    expected_network_id: &super::PyNetworkId,
    expected_chain: &str,
    expected_genesis_sha256: &Bound<'_, PyBytes>,
) -> PyResult<(String, Py<PyBytes>, String)> {
    let fail = |error: Failure| error.into_py(py);
    if !genesis.is_exact_instance_of::<PyBytes>()
        || !expected_genesis_sha256.is_exact_instance_of::<PyBytes>()
        || !proof_wires.is_exact_instance_of::<PyTuple>()
        || !(2..=MAX_PROOFS).contains(&proof_wires.len())
    {
        return Err(fail(Failure::Input(
            "require exact immutable bytes and a bounded exact tuple of proof frames",
        )));
    }
    let mut owners = Vec::new();
    owners
        .try_reserve_exact(proof_wires.len())
        .map_err(|e| fail(Failure::Allocation(e)))?;
    let mut total = 0usize;
    for item in proof_wires.iter() {
        if !item.is_exact_instance_of::<PyBytes>() {
            return Err(fail(Failure::Input(
                "each proof frame must be exact immutable bytes",
            )));
        }
        let bytes = item.cast_into::<PyBytes>()?;
        total = total
            .checked_add(bytes.as_bytes().len())
            .ok_or_else(|| fail(Failure::Input("proof byte count overflow")))?;
        if bytes.as_bytes().is_empty() || total > MAX_PROOF_BYTES {
            return Err(fail(Failure::Input(
                "proof frames exceed the closed aggregate byte bound",
            )));
        }
        owners.push(bytes);
    }
    let mut wires = Vec::new();
    wires
        .try_reserve_exact(owners.len())
        .map_err(|e| fail(Failure::Allocation(e)))?;
    wires.extend(owners.iter().map(|wire| wire.as_bytes()));
    let output = authenticate(
        genesis.as_bytes(),
        &wires,
        *expected_network_id.as_inner(),
        expected_chain,
        expected_genesis_sha256.as_bytes(),
    )
    .map_err(fail)?;
    Ok((
        output.metadata_json,
        PyBytes::new(py, &output.checkpoint).unbind(),
        output.tip_proof_chain_json,
    ))
}
pub(super) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add(
        "PublicFinalityReadError",
        module.py().get_type::<PublicFinalityReadError>(),
    )?;
    module.add_function(wrap_pyfunction!(
        authenticate_public_finality_checkpoint_v1,
        module
    )?)
}
#[cfg(test)]
#[path = "tests/public_finality_checkpoint_tests.rs"]
mod tests;
