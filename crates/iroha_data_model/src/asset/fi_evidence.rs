//! Staged shared native FI assertion carrier; no field is authenticated by decoding.
//!
//! Proposed destination: iroha_data_model::asset::fi_evidence. Native owns public
//! registration. The assertion/snapshot types are the staged v3 native contract.

use norito::{Decode, Encode};

use super::fi_context::AssetFiContextSnapshotV1;
use crate::sumeragi_finality::SumeragiFinalityProof;

/// First-release operational envelope. A real positive native fixture must fit
/// before endpoint qualification; this does not raise shared proof/relay limits.
pub const MAX_ASSET_FI_CONTEXT_CAPSULE_BYTES_V1: usize = 512 * 1024;

/// Original typed snapshot and certified assertion carrier. These are candidates
/// until the native verifier authenticates every field against independent pins.
/// No full World, remote trust anchor, projected JSON or current-state timestamp.
#[derive(Clone, Debug, Decode, Encode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::asset::fi_evidence::AssetFiContextAssertionCapsuleV1")]
pub struct AssetFiContextAssertionCapsuleV1 {
    /// Exactly one. Future wire layouts use another explicit version/type.
    pub version: u8,
    /// Exact execution-cut value whose canonical native hash the assertion checks.
    pub snapshot: AssetFiContextSnapshotV1,
    /// Canonical SignedTransaction::encode_wire_v1 including its authorization.
    pub assertion_signed_transaction: Vec<u8>,
    /// Existing canonical QueryResponse selecting exactly the assertion's committed row.
    pub committed_transaction_response: Vec<u8>,
    /// Existing native consecutive finality frames rooted at the local checkpoint.
    pub finality_proof_chain: Vec<SumeragiFinalityProof>,
}

impl AssetFiContextAssertionCapsuleV1 {
    fn check_carrier_bounds(&self) -> Result<(), String> {
        if self.version != 1
            || self.assertion_signed_transaction.is_empty()
            || self.assertion_signed_transaction.len() > MAX_ASSET_FI_CONTEXT_CAPSULE_BYTES_V1
            || self.committed_transaction_response.is_empty()
            || self.committed_transaction_response.len() > MAX_ASSET_FI_CONTEXT_CAPSULE_BYTES_V1
            || self.finality_proof_chain.is_empty()
            || self.finality_proof_chain.len() > 4096
        {
            return Err("invalid FI context capsule version or component bound".into());
        }
        Ok(())
    }

    /// Encodes exactly the retained candidate. It authenticates no ledger result.
    pub fn encode_canonical(&self) -> Result<Vec<u8>, String> {
        self.check_carrier_bounds()?;
        let size = norito::canonical_frame_len(self).map_err(|error| error.to_string())?;
        if size == 0 || size > MAX_ASSET_FI_CONTEXT_CAPSULE_BYTES_V1 {
            return Err("FI context capsule exceeds its operational bound".into());
        }
        let encoded = norito::encode_canonical(self).map_err(|error| error.to_string())?;
        if encoded.len() != size {
            return Err("FI context capsule sizing mismatch".into());
        }
        Ok(encoded)
    }

    /// One bounded canonical native frame; returned fields remain untrusted.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > MAX_ASSET_FI_CONTEXT_CAPSULE_BYTES_V1 {
            return Err("FI context capsule exceeds its operational bound".into());
        }
        let value: Self = norito::decode_canonical_with_limits(
            bytes,
            norito::canonical_decode_limits(bytes.len()),
        )
        .map_err(|error| error.to_string())?;
        value.check_carrier_bounds()?;
        Ok(value)
    }
}
