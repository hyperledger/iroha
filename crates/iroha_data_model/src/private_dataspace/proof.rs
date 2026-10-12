//! Compact public registration receipts checked against independently authenticated parent finality.

use super::*;
use crate::sumeragi_amx::AmxWriteProofV1;
use crate::sumeragi_finality::VerifiedSumeragiBlock;

/// Maximum canonical private-root record proof, including duplicate retained committee context.
pub const MAX_PRIVATE_DATASPACE_RECORD_PROOF_BYTES: usize = 128 * 1024;

/// A public record's inclusion in one exact certified parent execution.
///
/// Decoding or constructing this value grants no authority. The recipient must first authenticate
/// the parent using an independently selected genesis/checkpoint, then call [`Self::verify`].
/// This receipt describes ownership and the child cursor at its parent height, not a fresh lease
/// observation. It contains no private child body, genesis, artifact or execution write set.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::private_dataspace::PrivateDataspaceRecordProof")]
#[norito(deny_unknown_fields)]
pub struct PrivateDataspaceRecordProof {
    /// Exact parent genesis identity.
    pub parent_network_id: NetworkId,
    /// Certified non-genesis parent height that wrote the record.
    pub parent_height: u64,
    /// Complete execution-result commitment `R` authenticated at that parent height.
    pub parent_result: [u8; 32],
    /// Public record as written at the named height.
    pub record: PrivateDataspaceRecord,
    /// Inclusion under the execution result's ordinary-write root.
    pub inclusion: AmxWriteProofV1,
}

impl PrivateDataspaceRecordProof {
    /// Decode a bounded structural proof; only [`Self::verify`] authenticates its contents.
    ///
    /// # Errors
    /// Rejects noncanonical wire bytes, excessive allocations or malformed record structure.
    pub fn decode(bytes: &[u8]) -> Result<Self, PrivateDataspaceAnchorError> {
        require(
            bytes.len() <= MAX_PRIVATE_DATASPACE_RECORD_PROOF_BYTES,
            "record proof exceeds wire bound",
        )?;
        let proof: Self = norito::decode_canonical_with_limits(
            bytes,
            part_limits(MAX_PRIVATE_DATASPACE_RECORD_PROOF_BYTES),
        )
        .map_err(codec_failure)?;
        proof.validate_structure()?;
        Ok(proof)
    }

    fn validate_structure(&self) -> Result<(), PrivateDataspaceAnchorError> {
        self.record.validate()?;
        require(
            self.parent_height > 1 && self.parent_result != [0; 32],
            "record proof requires certified non-genesis parent execution",
        )?;
        require(
            self.record.anchor.registration().parent_scope()?.0 == self.parent_network_id,
            "record proof names another parent network",
        )?;
        require(
            self.inclusion.siblings.len() <= 256,
            "record proof exceeds path bound",
        )
    }

    /// Project a record from its original archived write set. This does not authenticate parent finality.
    ///
    /// # Errors
    /// Rejects malformed records or when the final write at the reserved key differs from `record`.
    pub fn from_writes<'a>(
        parent_network_id: NetworkId,
        parent_height: u64,
        parent_result: [u8; 32],
        writes: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
        record: PrivateDataspaceRecord,
    ) -> Result<Self, PrivateDataspaceAnchorError> {
        let (inclusion, value) =
            AmxWriteProofV1::from_writes(writes, &record.witness_key()).map_err(amx_failure)?;
        require(
            value == norito::encode_canonical(&record).map_err(codec_failure)?,
            "record differs from the archived final write",
        )?;
        let proof = Self {
            parent_network_id,
            parent_height,
            parent_result,
            record,
            inclusion,
        };
        proof.validate_structure()?;
        Ok(proof)
    }

    /// Authenticate this exact requested dataspace record against an independently verified parent.
    ///
    /// The supplied capability is created only by the native contiguous finality verifier. Neither
    /// the peer's claimed committee nor this proof can select the parent's trust root.
    ///
    /// # Errors
    /// Rejects another dataspace, network, height, result or ordinary-write inclusion root.
    pub fn verify(
        &self,
        expected_dataspace: DataSpaceId,
        parent: &VerifiedSumeragiBlock,
    ) -> Result<(), PrivateDataspaceAnchorError> {
        self.validate_structure()?;
        require(
            self.record.dataspace_id == expected_dataspace,
            "record proof is for another dataspace",
        )?;
        require(
            self.parent_network_id == parent.commitment().schedule.current.network_id
                && self.parent_height == parent.height()
                && self.parent_result == parent.result().0,
            "record proof differs from independently authenticated parent execution",
        )?;
        let value = norito::encode_canonical(&self.record).map_err(codec_failure)?;
        let root = self
            .inclusion
            .root(&self.record.witness_key(), &value)
            .map_err(amx_failure)?;
        require(
            root == parent.execution().ordinary_writes_root,
            "record is not included in certified parent writes",
        )
    }
}

#[cfg(test)]
mod tests;
