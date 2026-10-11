//! SCCP v1 message, control and history proofs (spec §5.1.3, §5.1.6, §5.2.2, §5.3.2).
//!
//! The chain-agnostic proof bundles a destination checks against an attestation, with the
//! pure parts of the destination checks: payload binding to the destination (§5.1.3 step 4
//! without the clock), leaf recomputation from fields (never a supplied leaf), block inclusion
//! against `sccpRoot/messageCount`, and, in historical mode, inclusion of the block's history
//! leaf against `historyRoot/historySize`. Wallets use these to pre-check bundles fetched from
//! Torii before paying for a destination transaction.

use iroha_data_model::bridge::SccpNetworkV1;

use super::{
    constants::{CODEC_TON_ACCOUNT36, MAX_BLOCK_LEAVES},
    eip712::AttestationFieldsV1,
    hashes::{self, LeafError},
    history::verify_history_inclusion,
    merkle::{MerkleError, verify_block_inclusion},
    payload::{PayloadError, SccpTransferPayloadV1},
};

unit_error! {
    /// Proof verification errors (`BadProof()`, `BadPayload()` and `BadRecipient()` on EVM).
    pub enum ProofError {
        /// The attested block (or historical block) has no SCCP leaves.
        EmptyBlock => "the proven block has no SCCP messages",
        /// The historical block claims more than 512 leaves or a zero root.
        BadHistoricalBlock => "historical block fields are inconsistent",
        /// The payload does not decode under §3.2.
        BadPayload => "message payload violates the payload rules",
        /// The payload is not a Taira → destination payload for this deployment.
        WrongDestination => "message payload targets another destination, route or revision",
        /// The recipient is the destination contract itself.
        RecipientIsDestination => "message recipient is the destination contract",
        /// The control leaf fields are invalid.
        BadControl => "control proof fields are invalid",
        /// The block inclusion path fails.
        BadBlockPath => "leaf is not included in the attested block root",
        /// The history inclusion path fails.
        BadHistoryPath => "block is not included in the attested history root",
    }
}

impl From<PayloadError> for ProofError {
    fn from(_: PayloadError) -> Self {
        Self::BadPayload
    }
}

impl From<LeafError> for ProofError {
    fn from(_: LeafError) -> Self {
        Self::BadControl
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

/// `MessageProofV1 { payload, leafIndex, path }` (§5.2.2).
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct MessageProofV1 {
    /// The §3.2 payload bytes.
    pub payload: Vec<u8>,
    /// Commitment index of the transfer leaf in its block.
    pub leaf_index: u32,
    /// Block path (at most 9 siblings).
    pub path: Vec<[u8; 32]>,
}

/// `HistoryProofV1 { height, sccpRoot, messageCount, leafIndex, path }` (§5.2.2).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct HistoryBlockV1 {
    /// Height of the historical SCCP-bearing block.
    pub height: u64,
    /// Its commitment root.
    pub sccp_root: [u8; 32],
    /// Its leaf count.
    pub message_count: u32,
}

/// `HistoryProofV1` (§5.2.2): a historical block and its history path.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct HistoryProofV1 {
    /// The historical block.
    pub block: HistoryBlockV1,
    /// Index of the block's history leaf.
    pub leaf_index: u64,
    /// History path (at most 32 siblings).
    pub path: Vec<[u8; 32]>,
}

/// `ControlProofV1 { controlNonce, paused, leafIndex, path }` (§5.2.2).
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct ControlProofV1 {
    /// Control nonce (≥ 1, strictly increasing per deployment).
    pub control_nonce: u64,
    /// `true` pauses minting, `false` resumes it.
    pub paused: bool,
    /// Commitment index of the control leaf in its block.
    pub leaf_index: u32,
    /// Block path (at most 9 siblings).
    pub path: Vec<[u8; 32]>,
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

impl HistoryProofV1 {
    /// `history_leaf(height, sccpRoot, messageCount)` of the historical block.
    #[must_use]
    pub fn history_leaf(&self) -> [u8; 32] {
        hashes::history_leaf(
            self.block.height,
            &self.block.sccp_root,
            self.block.message_count,
        )
    }

    /// Verify the historical block against `attestation.historyRoot/historySize`.
    ///
    /// # Errors
    ///
    /// Returns [`ProofError::BadHistoricalBlock`] or [`ProofError::BadHistoryPath`].
    pub fn verify(&self, attestation: &AttestationFieldsV1) -> Result<(), ProofError> {
        if self.block.message_count == 0
            || self.block.message_count > MAX_BLOCK_LEAVES
            || self.block.sccp_root == [0; 32]
        {
            return Err(ProofError::BadHistoricalBlock);
        }
        verify_history_inclusion(
            &self.history_leaf(),
            self.leaf_index,
            attestation.history_size,
            &self.path,
            &attestation.history_root,
        )
        .map_err(|_| ProofError::BadHistoryPath)
    }
}

impl ControlProofV1 {
    /// The control leaf this proof claims, computed from the destination's own immutables.
    ///
    /// # Errors
    ///
    /// Returns [`ProofError::BadControl`] for a zero nonce, zero revision or a Taira target.
    pub fn leaf(
        &self,
        taira_network_id: &[u8; 32],
        destination: &DestinationV1,
    ) -> Result<[u8; 32], ProofError> {
        Ok(hashes::control_leaf(
            taira_network_id,
            destination.network,
            &destination.destination_word,
            destination.route_revision,
            self.control_nonce,
            self.paused,
        )?)
    }
}

fn check_block(
    leaf: &[u8; 32],
    leaf_index: u32,
    path: &[[u8; 32]],
    sccp_root: &[u8; 32],
    message_count: u32,
) -> Result<(), ProofError> {
    if message_count == 0 {
        return Err(ProofError::EmptyBlock);
    }
    verify_block_inclusion(leaf, leaf_index, message_count, path, sccp_root).map_err(|error| {
        match error {
            MerkleError::TooManyLeaves => ProofError::BadHistoricalBlock,
            _ => ProofError::BadBlockPath,
        }
    })
}

/// §5.1.3 steps 4–5 in direct mode (the deadline and consumed-set checks are the caller's).
///
/// # Errors
///
/// Returns the first failing [`ProofError`].
pub fn verify_transfer_direct(
    attestation: &AttestationFieldsV1,
    proof: &MessageProofV1,
    taira_network_id: &[u8; 32],
    destination: &DestinationV1,
) -> Result<VerifiedTransferV1, ProofError> {
    if attestation.message_count == 0 {
        return Err(ProofError::EmptyBlock);
    }
    let transfer = proof.transfer(taira_network_id, destination)?;
    check_block(
        &transfer.leaf,
        proof.leaf_index,
        &proof.path,
        &attestation.sccp_root,
        attestation.message_count,
    )?;
    Ok(transfer)
}

/// §5.1.3 historical mode: the transfer against the historical block, then the block against
/// the attestation's history root.
///
/// # Errors
///
/// Returns the first failing [`ProofError`].
pub fn verify_transfer_historical(
    attestation: &AttestationFieldsV1,
    history: &HistoryProofV1,
    proof: &MessageProofV1,
    taira_network_id: &[u8; 32],
    destination: &DestinationV1,
) -> Result<VerifiedTransferV1, ProofError> {
    let transfer = proof.transfer(taira_network_id, destination)?;
    check_block(
        &transfer.leaf,
        proof.leaf_index,
        &proof.path,
        &history.block.sccp_root,
        history.block.message_count,
    )?;
    history.verify(attestation)?;
    Ok(transfer)
}

/// §5.1.6 step 3 in direct mode (the nonce ordering is the caller's).
///
/// # Errors
///
/// Returns the first failing [`ProofError`].
pub fn verify_control_direct(
    attestation: &AttestationFieldsV1,
    proof: &ControlProofV1,
    taira_network_id: &[u8; 32],
    destination: &DestinationV1,
) -> Result<[u8; 32], ProofError> {
    if attestation.message_count == 0 {
        return Err(ProofError::EmptyBlock);
    }
    let leaf = proof.leaf(taira_network_id, destination)?;
    check_block(
        &leaf,
        proof.leaf_index,
        &proof.path,
        &attestation.sccp_root,
        attestation.message_count,
    )?;
    Ok(leaf)
}

/// §5.1.6 step 3 in historical mode.
///
/// # Errors
///
/// Returns the first failing [`ProofError`].
pub fn verify_control_historical(
    attestation: &AttestationFieldsV1,
    history: &HistoryProofV1,
    proof: &ControlProofV1,
    taira_network_id: &[u8; 32],
    destination: &DestinationV1,
) -> Result<[u8; 32], ProofError> {
    let leaf = proof.leaf(taira_network_id, destination)?;
    check_block(
        &leaf,
        proof.leaf_index,
        &proof.path,
        &history.block.sccp_root,
        history.block.message_count,
    )?;
    history.verify(attestation)?;
    Ok(leaf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1::{hashes::word_address, history::HistoryAccumulatorV1, merkle::PromoteOddTree};

    const TAIRA: [u8; 32] = [0x11; 32];

    fn destination() -> DestinationV1 {
        DestinationV1 {
            network: SccpNetworkV1::EthereumMainnet,
            route_revision: 1,
            destination_word: word_address(&[0x22; 20]),
        }
    }

    fn payload(nonce: u64, recipient: [u8; 20]) -> Vec<u8> {
        SccpTransferPayloadV1::outbound(
            SccpNetworkV1::EthereumMainnet,
            nonce,
            1,
            1_800_000_000_000,
            1_000,
            vec![1, 2, 3],
            recipient.to_vec(),
        )
        .unwrap()
        .encode()
        .unwrap()
    }

    struct Block {
        leaves: Vec<[u8; 32]>,
        tree: PromoteOddTree,
        payloads: Vec<Vec<u8>>,
    }

    fn block() -> Block {
        let dest = destination();
        let payloads: Vec<Vec<u8>> = (0..3).map(|nonce| payload(nonce, [0x33; 20])).collect();
        let mut leaves: Vec<[u8; 32]> = payloads
            .iter()
            .map(|bytes| {
                MessageProofV1 {
                    payload: bytes.clone(),
                    ..MessageProofV1::default()
                }
                .transfer(&TAIRA, &dest)
                .unwrap()
                .leaf
            })
            .collect();
        let control = ControlProofV1 {
            control_nonce: 1,
            paused: true,
            ..ControlProofV1::default()
        };
        leaves.push(control.leaf(&TAIRA, &dest).unwrap());
        let tree = PromoteOddTree::block(&leaves).unwrap();
        Block {
            leaves,
            tree,
            payloads,
        }
    }

    fn attestation(
        root: [u8; 32],
        count: u32,
        history: &HistoryAccumulatorV1,
    ) -> AttestationFieldsV1 {
        AttestationFieldsV1 {
            height: 50,
            sccp_root: root,
            message_count: count,
            history_root: history.root(),
            history_size: history.size(),
            roster_digest: [9; 32],
            ..AttestationFieldsV1::default()
        }
    }

    #[test]
    fn direct_transfer_and_control() {
        let block = block();
        let mut history = HistoryAccumulatorV1::new();
        history
            .append(&hashes::history_leaf(50, &block.tree.root(), 4))
            .unwrap();
        let attestation = attestation(block.tree.root(), 4, &history);
        let dest = destination();
        let proof = MessageProofV1 {
            payload: block.payloads[1].clone(),
            leaf_index: 1,
            path: block.tree.path(1).unwrap(),
        };
        let verified = verify_transfer_direct(&attestation, &proof, &TAIRA, &dest).unwrap();
        assert_eq!(verified.payload.nonce, 1);
        assert_eq!(verified.leaf, block.leaves[1]);
        let wrong_index = MessageProofV1 {
            leaf_index: 2,
            ..proof.clone()
        };
        assert_eq!(
            verify_transfer_direct(&attestation, &wrong_index, &TAIRA, &dest),
            Err(ProofError::BadBlockPath)
        );
        let control = ControlProofV1 {
            control_nonce: 1,
            paused: true,
            leaf_index: 3,
            path: block.tree.path(3).unwrap(),
        };
        assert_eq!(
            verify_control_direct(&attestation, &control, &TAIRA, &dest),
            Ok(block.leaves[3])
        );
        // The same fields with the other pause value, or another revision, do not verify.
        let resumed = ControlProofV1 {
            paused: false,
            ..control.clone()
        };
        assert_eq!(
            verify_control_direct(&attestation, &resumed, &TAIRA, &dest),
            Err(ProofError::BadBlockPath)
        );
        let other_revision = DestinationV1 {
            route_revision: 2,
            ..dest
        };
        assert_eq!(
            verify_control_direct(&attestation, &control, &TAIRA, &other_revision),
            Err(ProofError::BadBlockPath)
        );
        // A transfer proof offered at the control leaf position fails.
        let at_control = MessageProofV1 {
            payload: block.payloads[0].clone(),
            leaf_index: 3,
            path: block.tree.path(3).unwrap(),
        };
        assert_eq!(
            verify_transfer_direct(&attestation, &at_control, &TAIRA, &dest),
            Err(ProofError::BadBlockPath)
        );
        let empty = AttestationFieldsV1 {
            message_count: 0,
            ..attestation
        };
        assert_eq!(
            verify_transfer_direct(&empty, &proof, &TAIRA, &dest),
            Err(ProofError::EmptyBlock)
        );
    }

    #[test]
    fn historical_mode() {
        let block = block();
        let mut history = HistoryAccumulatorV1::new();
        history
            .append(&hashes::history_leaf(7, &[1; 32], 1))
            .unwrap();
        let old_leaf = hashes::history_leaf(50, &block.tree.root(), 4);
        history.append(&old_leaf).unwrap();
        history
            .append(&hashes::history_leaf(80, &[2; 32], 2))
            .unwrap();
        let history_leaves = [
            hashes::history_leaf(7, &[1; 32], 1),
            old_leaf,
            hashes::history_leaf(80, &[2; 32], 2),
        ];
        let latest = attestation([2; 32], 2, &history);
        let history_proof = HistoryProofV1 {
            block: HistoryBlockV1 {
                height: 50,
                sccp_root: block.tree.root(),
                message_count: 4,
            },
            leaf_index: 1,
            path: crate::v1::history::history_path(&history_leaves, 1).unwrap(),
        };
        let proof = MessageProofV1 {
            payload: block.payloads[2].clone(),
            leaf_index: 2,
            path: block.tree.path(2).unwrap(),
        };
        let dest = destination();
        let verified =
            verify_transfer_historical(&latest, &history_proof, &proof, &TAIRA, &dest).unwrap();
        assert_eq!(verified.payload.nonce, 2);
        let control = ControlProofV1 {
            control_nonce: 1,
            paused: true,
            leaf_index: 3,
            path: block.tree.path(3).unwrap(),
        };
        assert!(
            verify_control_historical(&latest, &history_proof, &control, &TAIRA, &dest).is_ok()
        );
        let mut bad_height = history_proof.clone();
        bad_height.block.height = 51;
        assert_eq!(
            verify_transfer_historical(&latest, &bad_height, &proof, &TAIRA, &dest),
            Err(ProofError::BadHistoryPath)
        );
        let mut zero_count = history_proof;
        zero_count.block.message_count = 0;
        assert_eq!(
            verify_control_historical(&latest, &zero_count, &control, &TAIRA, &dest),
            Err(ProofError::EmptyBlock)
        );
    }

    #[test]
    fn payload_binding() {
        let dest = destination();
        let self_recipient = MessageProofV1 {
            payload: payload(0, [0x22; 20]),
            ..MessageProofV1::default()
        };
        assert_eq!(
            self_recipient.transfer(&TAIRA, &dest),
            Err(ProofError::RecipientIsDestination)
        );
        let other_revision = DestinationV1 {
            route_revision: 9,
            ..dest
        };
        let proof = MessageProofV1 {
            payload: payload(0, [0x33; 20]),
            ..MessageProofV1::default()
        };
        assert_eq!(
            proof.transfer(&TAIRA, &other_revision),
            Err(ProofError::WrongDestination)
        );
        let bsc = DestinationV1 {
            network: SccpNetworkV1::BscMainnet,
            ..dest
        };
        assert_eq!(
            proof.transfer(&TAIRA, &bsc),
            Err(ProofError::WrongDestination)
        );
        let garbage = MessageProofV1 {
            payload: vec![1, 2, 3],
            ..MessageProofV1::default()
        };
        assert_eq!(garbage.transfer(&TAIRA, &dest), Err(ProofError::BadPayload));
        let zero_nonce = ControlProofV1::default();
        assert_eq!(zero_nonce.leaf(&TAIRA, &dest), Err(ProofError::BadControl));
    }

    #[test]
    fn is_self_per_codec() {
        let word = word_address(&[0x22; 20]);
        let dest = DestinationV1 {
            network: SccpNetworkV1::BscMainnet,
            route_revision: 1,
            destination_word: word,
        };
        assert!(dest.is_self(2, &[0x22; 20]));
        assert!(!dest.is_self(2, &[0x23; 20]));
        // The retired 21-byte TRON form (`0x41` then the address) names no deployment.
        let mut retired = vec![0x41];
        retired.extend_from_slice(&[0x22; 20]);
        assert!(!dest.is_self(5, &retired));
        let ton_dest = DestinationV1 {
            network: SccpNetworkV1::TonMainnet,
            route_revision: 1,
            destination_word: [0x44; 32],
        };
        let mut ton_account = vec![0; 4];
        ton_account.extend_from_slice(&[0x44; 32]);
        assert!(ton_dest.is_self(CODEC_TON_ACCOUNT36, &ton_account));
        ton_account[35] = 0;
        assert!(!ton_dest.is_self(CODEC_TON_ACCOUNT36, &ton_account));
    }
}
