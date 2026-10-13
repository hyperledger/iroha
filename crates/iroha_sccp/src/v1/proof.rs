//! Current SCCP proof checks against an already authenticated finality header (§5.1.5–§5.1.6).
//!
//! The certificate and destination committee must be authenticated by the caller. Each proof
//! carries its actual block reference, checked by the same kernel the destination uses;
//! direct and historical inclusion use one current layout. No payload or control leaf is trusted.
use super::{
    constants::CODEC_TON_ACCOUNT36,
    control::{ControlLeafV1, check_control_constraints, control_leaf, control_leaf_unchecked},
    destination::{ControlProofV1, MessageProofV1, check_block_ref, check_leaf},
    finality::SccpFinalityHeaderV1,
    hashes,
    payload::{PayloadError, SccpTransferPayloadV1},
};
use iroha_data_model::bridge::SccpNetworkV1;
unit_error! {
    /// Failure of a leaf proof, independently of certificate authenticity and destination time.
    pub enum ProofError {
        /// The payload does not decode under §3.2.
        BadPayload => "message payload violates the payload rules",
        /// The payload targets another network or route revision.
        WrongDestination => "message payload targets another destination, route or revision",
        /// The recipient is this destination contract.
        RecipientIsDestination => "message recipient is the destination contract",
        /// The control fields violate §3.4.
        BadControl => "control proof fields are invalid",
        /// The block reference is not included in this active header of the selected network.
        BadBlockReference => "leaf block is not included in the certified header",
        /// The leaf path does not match its claimed block.
        BadBlockPath => "leaf is not included in the certified block root",
    }
}
impl From<PayloadError> for ProofError {
    fn from(_: PayloadError) -> Self {
        Self::BadPayload
    }
}
/// A destination deployment as its own contract sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DestinationV1 {
    /// External network of the deployment.
    pub network: SccpNetworkV1,
    /// Route revision bound to the deployment.
    pub route_revision: u32,
    /// Contract-visible destination word (§3.4).
    pub destination_word: [u8; 32],
}

impl DestinationV1 {
    /// Whether `recipient` (payload bytes of the own codec) names this deployment itself.
    #[must_use]
    pub fn is_self(&self, recipient_codec: u8, recipient: &[u8]) -> bool {
        match recipient_codec {
            CODEC_TON_ACCOUNT36 => recipient.len() == 36 && recipient[4..] == self.destination_word,
            // EVM: word(address) of the recipient.
            _ => recipient.len() == 20 && recipient == &self.destination_word[12..],
        }
    }
}

/// A verified transfer: the decoded payload, its message id and its leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTransferV1 {
    /// Decoded payload.
    pub payload: SccpTransferPayloadV1,
    /// `message_id` (§3.3).
    pub message_id: [u8; 32],
    /// Transfer leaf (§3.4).
    pub leaf: [u8; 32],
}

impl MessageProofV1 {
    /// Decode the payload, check that it is a Taira → `destination` payload for its route and
    /// revision with a recipient other than the deployment, and compute its message id and leaf.
    ///
    /// # Errors
    ///
    /// Returns [`ProofError::BadPayload`], [`ProofError::WrongDestination`] or
    /// [`ProofError::RecipientIsDestination`].
    pub fn transfer(
        &self,
        taira_network_id: &[u8; 32],
        destination: &DestinationV1,
    ) -> Result<VerifiedTransferV1, ProofError> {
        let payload = SccpTransferPayloadV1::decode(&self.payload)?;
        if !payload.is_outbound()
            || payload.target() != Some(destination.network)
            || payload.route_revision != destination.route_revision
        {
            return Err(ProofError::WrongDestination);
        }
        if destination.is_self(payload.recipient.codec, &payload.recipient.bytes) {
            return Err(ProofError::RecipientIsDestination);
        }
        let message_id = payload.message_id(taira_network_id)?;
        let leaf = hashes::transfer_leaf(&message_id, &destination.destination_word);
        Ok(VerifiedTransferV1 {
            payload,
            message_id,
            leaf,
        })
    }
}

impl ControlProofV1 {
    /// The exact authority fields committed by this proof, using the selected deployment's revision.
    #[must_use]
    pub const fn fields(&self, route_revision: u32) -> ControlLeafV1 {
        ControlLeafV1 {
            route_revision,
            control_nonce: self.control_nonce,
            track: self.track,
            parliament_paused: self.parliament_paused,
            fast_pause_until_ms: self.fast_pause_until_ms,
            certificate_id: self.certificate_id,
            effect_hash: self.effect_hash,
        }
    }
    /// Compute the current 199-byte control leaf from the selected deployment and valid fields.
    ///
    /// # Errors
    /// Returns `BadControl` for any violated control-field constraint.
    pub fn leaf(
        &self,
        network_id: &[u8; 32],
        destination: &DestinationV1,
    ) -> Result<[u8; 32], ProofError> {
        control_leaf(
            network_id,
            destination.network,
            &destination.destination_word,
            &self.fields(destination.route_revision),
        )
        .map_err(|_| ProofError::BadControl)
    }
}
fn check_header(header: &SccpFinalityHeaderV1, network_id: &[u8; 32]) -> Result<(), ProofError> {
    if header.is_active() && header.network_id() == *network_id {
        Ok(())
    } else {
        Err(ProofError::BadBlockReference)
    }
}
/// Check a current transfer proof against a verified active header and the destination's own identity.
/// The deadline, pause, consumed-set and committee state rules are the caller's responsibility.
///
/// # Errors
/// Returns the first violated payload, block-reference or leaf-inclusion check.
pub fn verify_transfer(
    header: &SccpFinalityHeaderV1,
    proof: &MessageProofV1,
    network_id: &[u8; 32],
    destination: &DestinationV1,
) -> Result<VerifiedTransferV1, ProofError> {
    check_header(header, network_id)?;
    check_block_ref(&proof.block, header).map_err(|_| ProofError::BadBlockReference)?;
    let transfer = proof.transfer(network_id, destination)?;
    check_leaf(&transfer.leaf, proof.leaf_index, &proof.path, &proof.block)
        .map_err(|_| ProofError::BadBlockPath)?;
    Ok(transfer)
}
/// Check a current two-track control proof, including all cause and expiry commitments.
/// Like the destination, verify the leaf before checking the control-field constraints.
/// Nonce freshness and destination-time expiry clamping belong to the caller.
///
/// # Errors
/// Returns the first violated header, inclusion or control-field check.
pub fn verify_control(
    header: &SccpFinalityHeaderV1,
    proof: &ControlProofV1,
    network_id: &[u8; 32],
    destination: &DestinationV1,
) -> Result<[u8; 32], ProofError> {
    check_header(header, network_id)?;
    check_block_ref(&proof.block, header).map_err(|_| ProofError::BadBlockReference)?;
    let fields = proof.fields(destination.route_revision);
    let leaf = control_leaf_unchecked(
        network_id,
        destination.network,
        &destination.destination_word,
        &fields,
    )
    .map_err(|_| ProofError::BadControl)?;
    check_leaf(&leaf, proof.leaf_index, &proof.path, &proof.block)
        .map_err(|_| ProofError::BadBlockPath)?;
    check_control_constraints(&fields).map_err(|_| ProofError::BadControl)?;
    Ok(leaf)
}
#[cfg(test)]
mod tests;
