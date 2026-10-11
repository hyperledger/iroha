//! The actual twelve-field header and five-field confidential digest Copy walks.
//!
//! These are the original record codecs, not the payload-only header tuple adapter.

use super::BlockHeader;
use crate::{
    confidential::ConfidentialFeatureDigest,
    inline_fields::{InlineFields, InlineLeaf},
};
use norito::core::{DecodeIntoError, DecodeRecordFields, Error};

impl InlineLeaf for ConfidentialFeatureDigest {
    fn read(bytes: &[u8]) -> Result<Self, Error> {
        let (
            (
                vk_set_hash,
                poseidon_params_id,
                pedersen_params_id,
                conf_rules_version,
                zk_policy_hash,
            ),
            used,
        ) = Self::decode_fields(bytes, &mut InlineFields).map_err(DecodeIntoError::into_codec)?;
        if used != bytes.len() {
            return Err(Error::LengthMismatch);
        }
        Ok(Self {
            vk_set_hash,
            poseidon_params_id,
            pedersen_params_id,
            conf_rules_version,
            zk_policy_hash,
        })
    }
}

impl BlockHeader {
    /// Decode the complete original record payload into its twelve inline fields.
    ///
    /// The same generated walk owns prefixes, ordering and all canonical child
    /// codecs. The caller installs the actual layout flags and logical decode
    /// scope; a prepared signed block does this in its original header field.
    /// No owning alignment copy or heap child is introduced. These Copy values
    /// remain in the retained block's original prepaid containing control.
    ///
    /// This is transport decoding only. It authenticates no ancestry, genesis,
    /// proposal commitment, signature, execution result or finality. Those remain
    /// subject to their existing complete-source and protocol validators. Neither
    /// a standalone decoded header nor a nullable hash grants custody authority.
    ///
    /// # Errors
    /// Returns the original `NonZero`, Option, marked-hash, child/field/depth limit
    /// or complete-consumption failure without reclassifying a local refusal.
    pub fn decode_inline_payload(bytes: &[u8]) -> Result<Self, Error> {
        let (
            (
                height,
                prev_block_hash,
                merkle_root,
                da_proof_policies_hash,
                da_commitments_hash,
                da_pin_intents_hash,
                npos_effects_hash,
                creation_time_ms,
                view_change_index,
                confidential_features,
                execution_context_hash,
                global_beacon_pulse_hash,
            ),
            used,
        ) = Self::decode_fields(bytes, &mut InlineFields).map_err(DecodeIntoError::into_codec)?;
        if used != bytes.len() {
            return Err(Error::LengthMismatch);
        }
        Ok(Self {
            height,
            prev_block_hash,
            merkle_root,
            da_proof_policies_hash,
            da_commitments_hash,
            da_pin_intents_hash,
            npos_effects_hash,
            creation_time_ms,
            view_change_index,
            confidential_features,
            execution_context_hash,
            global_beacon_pulse_hash,
        })
    }
}

#[cfg(test)]
mod tests;
