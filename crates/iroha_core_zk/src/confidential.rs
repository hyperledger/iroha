//! Wallet-facing confidential proving with canonical relation and key selection.
//!
//! Construct one [`ConfidentialProver`] for an exact network and canonical asset,
//! then supply owned note openings and an authenticated tree snapshot. The
//! prover selects the circuit, checks input shape before key preparation, uses
//! operating-system proof randomness, and verifies its output before returning.
//! Applications must select an implemented protocol-owned admission path that
//! checks its required key, root, nullifiers and authority; a local proof alone
//! does not authorize a ledger change.

use iroha_data_model::{NetworkId, asset::AssetDefinitionId, proof::ProofBox};
use zeroize::Zeroizing;

use super::{ProofRelation, confidential_v2 as native};

/// Actionable wallet preflight or native proving failure.
///
/// Callers can distinguish malformed inputs from key preparation and proof
/// failures without parsing text. Preflight messages never include note values,
/// spend keys, nonces or path contents.
#[derive(Debug, thiserror::Error)]
pub enum ConfidentialProverError {
    /// The reserved all-zero spend key is invalid.
    #[error("confidential spend key must not be all zero")]
    InvalidSpendKey,
    /// The circuit spends one or two actual notes.
    #[error("confidential spending requires one or two input notes")]
    InputCount,
    /// The supplied tree exceeds the fixed circuit capacity.
    #[error("confidential tree exceeds its 65,536-leaf capacity")]
    TreeCapacity,
    /// The path count differs from the actual input count.
    #[error("supply exactly one membership path per input note")]
    PathCount,
    /// A path has invalid dimensions, nonboolean directions or the wrong root.
    #[error("membership path has an invalid shape or expected root")]
    InvalidPath,
    /// The input index lies outside the supplied tree or fixed capacity.
    #[error("input note index lies outside the supplied tree")]
    InputIndex,
    /// The path direction bits describe a different input leaf.
    #[error("membership path directions do not match the input note index")]
    PathIndexMismatch,
    /// Two inputs refer to the same note.
    #[error("a confidential spend cannot consume the same note twice")]
    DuplicateInput,
    /// The circuit creates one or two actual notes.
    #[error("confidential transfer requires one or two output notes")]
    OutputCount,
    /// Transfer values are zero, overflow, or fail conservation.
    #[error("confidential transfer needs positive note amounts and equal non-overflowing totals")]
    InvalidTransferAmounts,
    /// Input values are zero or overflow their sum.
    #[error("confidential inputs require positive amounts with a non-overflowing total")]
    InvalidInputAmounts,
    /// The public amount is zero or exceeds the consumed value.
    #[error("public redemption amount must be positive and no greater than the input total")]
    InvalidPublicAmount,
    /// Change is absent, unnecessary, or differs from the remaining value.
    #[error("supply one change note for a nonzero remainder and none for full redemption")]
    InvalidChange,
    /// The canonical native proving key could not be prepared.
    #[error("confidential key preparation failed: {0}")]
    KeyPreparation(#[source] iroha_plonk::verification_attempt::NativeVerifierInitError),
    /// Native membership, relation, proof generation or self-verification failed.
    #[error("confidential proof generation failed: {0}")]
    Proving(#[source] native::ConfidentialProofProductionError),
}

impl native::ConfidentialUnshieldOutputV3 {
    /// Consume a saved change opening as an input at its authenticated leaf index.
    ///
    /// Securely persist the opening before proving consumes the original, then
    /// restore it once its ledger position is authenticated. Change belongs to
    /// the wallet's default diversifier, even when the consumed note used a
    /// different diversifier. This conversion checks shape, not membership.
    ///
    /// # Errors
    ///
    /// Returns `InputIndex` if the index is outside the fixed tree capacity, or
    /// `InvalidInputAmounts` if the saved change amount is zero. The consumed
    /// opening is still cleared on failure.
    pub fn into_input(
        mut self,
        leaf_index: usize,
    ) -> Result<native::ConfidentialUnshieldInputV2, ConfidentialProverError> {
        if leaf_index >= native::CONFIDENTIAL_TREE_CAPACITY_V2 {
            return Err(ConfidentialProverError::InputIndex);
        }
        if self.amount == 0 {
            return Err(ConfidentialProverError::InvalidInputAmounts);
        }
        Ok(native::ConfidentialUnshieldInputV2 {
            amount: std::mem::take(&mut self.amount),
            rho: std::mem::take(&mut self.rho),
            diversifier: native::default_confidential_diversifier_v2(),
            leaf_index,
        })
    }
}

/// Borrowed tree evidence for precisely the notes being spent.
///
/// Obtain `root` from authenticated ledger state. A full tree is useful for
/// local wallets; remote wallets can supply one path per actual input instead.
/// No absent-input path is required. Membership is verified during proving.
pub enum ConfidentialTree<'a> {
    /// Ordered commitment leaves and their expected ledger root.
    Commitments {
        /// Authenticated expected root.
        root: [u8; 32],
        /// Complete ordered commitment prefix, at most 65,536 leaves.
        leaves: &'a [[u8; 32]],
    },
    /// Ordered membership paths corresponding one-for-one to the input notes.
    Paths {
        /// Authenticated expected root.
        root: [u8; 32],
        /// Exactly one path per actual note, in input order.
        paths: &'a [native::ConfidentialMerklePathV2],
    },
}

impl ConfidentialTree<'_> {
    fn validate(
        &self,
        indices: impl ExactSizeIterator<Item = usize>,
    ) -> Result<(), ConfidentialProverError> {
        const CAPACITY: usize = 1 << native::CONFIDENTIAL_TREE_DEPTH_V2;
        if !(1..=2).contains(&indices.len()) {
            return Err(ConfidentialProverError::InputCount);
        }
        let leaf_bound = match self {
            Self::Commitments { leaves, .. } => {
                if leaves.len() > CAPACITY {
                    return Err(ConfidentialProverError::TreeCapacity);
                }
                leaves.len()
            }
            Self::Paths { root, paths } => {
                if paths.len() != indices.len() {
                    return Err(ConfidentialProverError::PathCount);
                }
                for path in *paths {
                    if path.root != *root
                        || path.siblings.len() != native::CONFIDENTIAL_TREE_DEPTH_V2
                        || path.directions.len() != native::CONFIDENTIAL_TREE_DEPTH_V2
                        || (!path.witness_nodes.is_empty()
                            && path.witness_nodes.len() != native::CONFIDENTIAL_TREE_DEPTH_V2)
                        || path.directions.iter().any(|direction| *direction > 1)
                    {
                        return Err(ConfidentialProverError::InvalidPath);
                    }
                }
                CAPACITY
            }
        };
        let mut first = None;
        for (position, index) in indices.enumerate() {
            if index >= leaf_bound {
                return Err(ConfidentialProverError::InputIndex);
            }
            if let Self::Paths { paths, .. } = self {
                if paths[position]
                    .directions
                    .iter()
                    .enumerate()
                    .any(|(level, &direction)| usize::from(direction) != ((index >> level) & 1))
                {
                    return Err(ConfidentialProverError::PathIndexMismatch);
                }
            }
            if first == Some(index) {
                return Err(ConfidentialProverError::DuplicateInput);
            }
            first = Some(index);
        }
        Ok(())
    }
}

/// Public output of a locally generated and self-verified confidential proof.
///
/// This is transaction material, not a ledger authorization or confirmation.
#[derive(Debug, Clone)]
pub struct ConfidentialProof {
    /// Exact relation chosen by the prover.
    pub relation: ProofRelation,
    /// Proof envelope for the corresponding canonical key.
    pub proof: ProofBox,
    /// Authenticated input root bound by the proof.
    pub root: [u8; 32],
    /// Consumed note nullifiers, in input order.
    pub nullifiers: Vec<[u8; 32]>,
    /// Created commitments, empty for full redemption.
    pub output_commitments: Vec<[u8; 32]>,
}

/// Confidential prover bound to one network, asset and privately owned spend key.
///
/// The spend key is cleared on drop; this type is neither clonable nor
/// serializable. Input and output openings are consumed and cleared by their
/// native owners on success and failure. Only public proof material is returned.
pub struct ConfidentialProver {
    network: NetworkId,
    asset: String,
    spend_key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for ConfidentialProver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ConfidentialProver { private_context: [REDACTED] }")
    }
}

impl ConfidentialProver {
    /// Bind canonical identifiers and take ownership of the wallet spend key.
    ///
    /// Returns an error for the reserved all-zero key. No key generation, tree
    /// hashing or proof work occurs here. Obtain the key from secure wallet
    /// storage; never derive production keys from example constants.
    ///
    /// # Errors
    ///
    /// Returns `InvalidSpendKey` for an all-zero spend key. The rejected owned
    /// key is cleared when dropped.
    pub fn new(
        network: NetworkId,
        asset: &AssetDefinitionId,
        spend_key: Zeroizing<[u8; 32]>,
    ) -> Result<Self, ConfidentialProverError> {
        if spend_key.iter().all(|byte| *byte == 0) {
            return Err(ConfidentialProverError::InvalidSpendKey);
        }
        Ok(Self {
            network,
            asset: asset.to_string(),
            spend_key,
        })
    }

    /// Prove a transfer of one or two notes to one or two output notes.
    ///
    /// Amount conservation, ownership and membership are enforced by the native
    /// relation. Circuit IDs, verifier keys and transcript internals are selected
    /// internally. Shape errors reject before preparing the canonical key.
    ///
    /// # Errors
    ///
    /// Returns a preflight error for invalid tree shape, input indices or paths,
    /// duplicate inputs, invalid output count, or nonpositive, overflowing or
    /// unequal amount totals. Returns `KeyPreparation` if the canonical key cannot
    /// be prepared, or `Proving` if native membership, relation construction,
    /// proof generation or self-verification fails. Consumed openings are cleared
    /// on both success and failure.
    pub fn prove_transfer(
        &self,
        tree: ConfidentialTree<'_>,
        inputs: Vec<native::ConfidentialTransferInputV2>,
        outputs: Vec<native::ConfidentialTransferOutputV2>,
    ) -> Result<ConfidentialProof, ConfidentialProverError> {
        tree.validate(inputs.iter().map(|input| input.leaf_index))?;
        if !(1..=2).contains(&outputs.len()) {
            return Err(ConfidentialProverError::OutputCount);
        }
        let input_total = positive_total(inputs.iter().map(|input| input.amount));
        let output_total = positive_total(outputs.iter().map(|output| output.amount));
        if input_total.is_none() || input_total != output_total {
            return Err(ConfidentialProverError::InvalidTransferAmounts);
        }
        let key = native::confidential_transfer_v2_vk_box()
            .map_err(ConfidentialProverError::KeyPreparation)?;
        let circuit = native::CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID;
        let result = match tree {
            ConfidentialTree::Commitments { root, leaves } => {
                native::build_confidential_transfer_proof_v2(
                    &self.network,
                    &self.asset,
                    self.spend_key.as_ref(),
                    leaves,
                    &inputs,
                    &outputs,
                    root,
                    circuit,
                    &key,
                )
            }
            ConfidentialTree::Paths { root, paths } => {
                native::build_confidential_transfer_proof_v2_with_paths(
                    &self.network,
                    &self.asset,
                    self.spend_key.as_ref(),
                    paths,
                    &inputs,
                    &outputs,
                    root,
                    circuit,
                    &key,
                )
            }
        }
        .map_err(ConfidentialProverError::Proving)?;
        Ok(ConfidentialProof {
            relation: ProofRelation::ConfidentialTransfer,
            proof: result.proof,
            root: result.root,
            nullifiers: result.nullifiers,
            output_commitments: result.output_commitments,
        })
    }

    /// Redeem notes, selecting full redemption or private change automatically.
    ///
    /// Supply `None` when redeeming the entire value. Otherwise supply one change
    /// opening whose amount equals the remainder. This method never invents a
    /// note nonce or requires a dummy input. Native proving checks conservation.
    ///
    /// # Errors
    ///
    /// Returns a preflight error for invalid tree evidence or inputs, nonpositive
    /// or overflowing input totals, an invalid public amount, or incorrect change.
    /// Returns `KeyPreparation` if the selected canonical key cannot be prepared,
    /// or `Proving` if native membership, relation construction, proof generation
    /// or self-verification fails. Consumed openings are cleared on either outcome.
    pub fn prove_unshield(
        &self,
        tree: ConfidentialTree<'_>,
        inputs: Vec<native::ConfidentialUnshieldInputV2>,
        public_amount: u128,
        change: Option<native::ConfidentialUnshieldOutputV3>,
    ) -> Result<ConfidentialProof, ConfidentialProverError> {
        tree.validate(inputs.iter().map(|input| input.leaf_index))?;
        let total = positive_total(inputs.iter().map(|input| input.amount))
            .ok_or(ConfidentialProverError::InvalidInputAmounts)?;
        if public_amount == 0 || public_amount > total {
            return Err(ConfidentialProverError::InvalidPublicAmount);
        }
        let remainder = total - public_amount;
        if change.as_ref().map_or(0, |note| note.amount) != remainder
            || (change.is_some() && remainder == 0)
        {
            return Err(ConfidentialProverError::InvalidChange);
        }
        if let Some(change) = change {
            let key = native::confidential_unshield_v3_vk_box()
                .map_err(ConfidentialProverError::KeyPreparation)?;
            let circuit = native::CONFIDENTIAL_UNSHIELD_V3_CIRCUIT_ID;
            let outputs = [change];
            let result = match tree {
                ConfidentialTree::Commitments { root, leaves } => {
                    native::build_confidential_unshield_proof_v3(
                        &self.network,
                        &self.asset,
                        self.spend_key.as_ref(),
                        leaves,
                        &inputs,
                        &outputs,
                        public_amount,
                        root,
                        circuit,
                        &key,
                    )
                }
                ConfidentialTree::Paths { root, paths } => {
                    native::build_confidential_unshield_proof_v3_with_paths(
                        &self.network,
                        &self.asset,
                        self.spend_key.as_ref(),
                        paths,
                        &inputs,
                        &outputs,
                        public_amount,
                        root,
                        circuit,
                        &key,
                    )
                }
            }
            .map_err(ConfidentialProverError::Proving)?;
            return Ok(ConfidentialProof {
                relation: ProofRelation::ConfidentialChangeUnshield,
                proof: result.proof,
                root: result.root,
                nullifiers: result.nullifiers,
                output_commitments: result.output_commitments,
            });
        }
        let key = native::confidential_unshield_v2_vk_box()
            .map_err(ConfidentialProverError::KeyPreparation)?;
        let circuit = native::CONFIDENTIAL_UNSHIELD_V2_CIRCUIT_ID;
        let result = match tree {
            ConfidentialTree::Commitments { root, leaves } => {
                native::build_confidential_unshield_proof_v2(
                    &self.network,
                    &self.asset,
                    self.spend_key.as_ref(),
                    leaves,
                    &inputs,
                    public_amount,
                    root,
                    circuit,
                    &key,
                )
            }
            ConfidentialTree::Paths { root, paths } => {
                native::build_confidential_unshield_proof_v2_with_paths(
                    &self.network,
                    &self.asset,
                    self.spend_key.as_ref(),
                    paths,
                    &inputs,
                    public_amount,
                    root,
                    circuit,
                    &key,
                )
            }
        }
        .map_err(ConfidentialProverError::Proving)?;
        Ok(ConfidentialProof {
            relation: ProofRelation::ConfidentialFullUnshield,
            proof: result.proof,
            root: result.root,
            nullifiers: result.nullifiers,
            output_commitments: Vec::new(),
        })
    }
}

fn positive_total(mut amounts: impl Iterator<Item = u128>) -> Option<u128> {
    amounts.try_fold(0, |sum: u128, amount| {
        if amount == 0 {
            None
        } else {
            sum.checked_add(amount)
        }
    })
}

#[cfg(test)]
mod tests;
