//! Structures related to proofs and reasons of view changes.
//! Where view change is a process of changing topology due to some faulty network behavior.

use std::{collections::HashSet, fmt::Display};

use eyre::{Context, Result};
use iroha_crypto::{HashOf, KeyPair, PublicKey, SignatureOf, SignaturesOf};
use iroha_data_model::{prelude::PeerId, transaction::VersionedTransaction};
use iroha_macro::*;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};

use super::message::TransactionReceipt;
use crate::block::{EmptyChainHash, VersionedCommittedBlock, VersionedValidBlock};

/// The proof of a view change. It needs to be signed by f+1 peers for proof to be valid and view change to happen.
#[derive(Clone, Debug, Io, Encode, Decode, IntoSchema)]
pub struct Proof {
    payload: ProofPayload,
    signatures: SignaturesOf<Self>,
}

impl Proof {
    fn hash(&self) -> HashOf<Self> {
        HashOf::new(&self.payload).transmute()
    }

    fn from_payload(payload: ProofPayload, key_pair: KeyPair) -> Result<Self> {
        let signatures = SignaturesOf::new(key_pair, &payload)
            .wrap_err("Failed to create proof of view change")?
            .transmute();
        Ok(Self {
            payload,
            signatures,
        })
    }

    /// Constructor for `CommitTimeout` view change suggestion.
    /// # Errors
    /// Fails if signing failed.
    pub fn commit_timeout(
        hash: HashOf<VersionedValidBlock>,
        previous_proof: HashOf<Self>,
        latest_block: HashOf<VersionedCommittedBlock>,
        key_pair: KeyPair,
    ) -> Result<Self> {
        let payload = ProofPayload {
            reason: Reason::CommitTimeout(CommitTimeout { hash }),
            previous_proof,
            latest_block,
        };
        Self::from_payload(payload, key_pair)
    }

    /// Constructor for `BlockCreationTimeout` view change suggestion.
    /// # Errors
    /// Can fail due to signing
    pub fn block_creation_timeout(
        transaction_receipt: TransactionReceipt,
        previous_proof: HashOf<Self>,
        latest_block: HashOf<VersionedCommittedBlock>,
        key_pair: KeyPair,
    ) -> Result<Self> {
        let payload = ProofPayload {
            reason: Reason::from(BlockCreationTimeout {
                transaction_receipt,
            }),
            previous_proof,
            latest_block,
        };
        Self::from_payload(payload, key_pair)
    }

    /// Constructor for `NoTransactionReceiptReceived` view change suggestion.
    /// # Errors
    /// Can fail due to signing
    pub fn no_transaction_receipt_received(
        transaction_hash: HashOf<VersionedTransaction>,
        previous_proof: HashOf<Self>,
        latest_block: HashOf<VersionedCommittedBlock>,
        key_pair: KeyPair,
    ) -> Result<Self> {
        let payload = ProofPayload {
            reason: Reason::NoTransactionReceiptReceived(NoTransactionReceiptReceived {
                transaction_hash,
            }),
            previous_proof,
            latest_block,
        };
        Self::from_payload(payload, key_pair)
    }

    /// Signs this message with the peer's public and private key.
    /// This way peers vote for changing the view - changing the roles of peers.
    ///
    /// # Errors
    /// Can fail during creation of signature
    pub fn sign(mut self, key_pair: KeyPair) -> Result<Proof> {
        let signature = SignatureOf::new(key_pair, &self.payload)?.transmute();
        self.signatures.add(signature);
        Ok(self)
    }

    /// Verify if the proof is valid, given the peers in `topology`.
    pub fn verify(&self, peers: &HashSet<PeerId>, max_faults: u32) -> bool {
        let peer_public_keys: HashSet<PublicKey> = peers
            .iter()
            .map(|peer_id| peer_id.public_key.clone())
            .collect();
        let n_signatures = self
            .signatures
            .verified_by_hash(self.hash())
            .filter(|signature| peer_public_keys.contains(&signature.public_key))
            .count();
        // See Whitepaper for the information on this limit.
        #[allow(clippy::int_plus_one)]
        {
            n_signatures >= max_faults as usize + 1
        }
    }

    /// Should be checked by validators before signing the proof.
    pub fn has_same_state(
        &self,
        latest_block: &HashOf<VersionedCommittedBlock>,
        latest_view_change: &HashOf<Proof>,
    ) -> bool {
        &self.payload.latest_block == latest_block
            && &self.payload.previous_proof == latest_view_change
    }

    /// The `Reason` of this view change. Why should topology change?
    pub const fn reason(&self) -> &Reason {
        &self.payload.reason
    }

    /// Signatures of peers who signed this proof - therefore voting for this view change.
    pub const fn signatures(&self) -> &SignaturesOf<Self> {
        &self.signatures
    }
}

/// Payload of [`Proof`]
#[derive(Clone, Debug, Io, Encode, Decode, IntoSchema)]
pub struct ProofPayload {
    ///
    previous_proof: HashOf<Proof>,
    /// Latest committed block hash.
    latest_block: HashOf<VersionedCommittedBlock>,
    ///
    reason: Reason,
}

/// Reason for a view change.
#[derive(Clone, Debug, Io, Encode, Decode, FromVariant, IntoSchema)]
pub enum Reason {
    /// Proxy tail have not committed a block in time.
    CommitTimeout(CommitTimeout),
    /// Transaction was sent to leader, but no corresponding receipt was received from the leader for it.
    NoTransactionReceiptReceived(NoTransactionReceiptReceived),
    /// Transaction reached leader but no block was created.
    BlockCreationTimeout(Box<BlockCreationTimeout>),
}

impl Display for Reason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Reason::CommitTimeout(_) => write!(f, "Commit Timeout"),
            Reason::NoTransactionReceiptReceived(_) => write!(f, "No Transaction Receipt Received"),
            Reason::BlockCreationTimeout(_) => write!(f, "Block Creation Timeout"),
        }
    }
}

/// Block `CommitTimeout` reason for a view change.
#[derive(Clone, Debug, Io, Encode, Decode, Copy, IntoSchema)]
pub struct CommitTimeout {
    /// The hash of the block in discussion in this round.
    pub hash: HashOf<VersionedValidBlock>,
}

/// `NoTransactionReceiptReceived` (from leader) reason for a view change.
#[derive(Clone, Debug, Io, Encode, Decode, Copy, IntoSchema)]
pub struct NoTransactionReceiptReceived {
    /// The hash of the transaction for which there was no `TransactionReceipt`.
    pub transaction_hash: HashOf<VersionedTransaction>,
}

/// `BlockCreationTimeout` reason for a view change.
#[derive(Clone, Debug, Io, Encode, Decode, IntoSchema)]
pub struct BlockCreationTimeout {
    /// A proof of the leader receiving and accepting a transaction.
    pub transaction_receipt: TransactionReceipt,
}

/// A chain of view change proofs. Stored in block for roles to be known at that point in history.
#[derive(Clone, Debug, Io, Encode, Decode, Default, IntoSchema)]
pub struct ProofChain {
    proofs: Vec<Proof>,
}

impl ProofChain {
    /// Initialize an empty proof chain.
    pub const fn empty() -> ProofChain {
        Self { proofs: Vec::new() }
    }

    /// Verify the view change proof chain.
    pub fn verify_with_state(
        &self,
        peers: &HashSet<PeerId>,
        max_faults: u32,
        latest_block: &HashOf<VersionedCommittedBlock>,
    ) -> bool {
        let mut previous_proof = EmptyChainHash::default().into();
        for proof in &self.proofs {
            if proof.has_same_state(latest_block, &previous_proof)
                && proof.verify(peers, max_faults)
            {
                previous_proof = proof.hash();
            } else {
                return false;
            }
        }
        true
    }

    /// Add a latest change proof on top.
    pub fn push(&mut self, proof: Proof) {
        self.proofs.push(proof)
    }

    /// The number of view change proofs in this proof chain.
    pub fn len(&self) -> usize {
        self.proofs.len()
    }

    /// Is proof chain empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The hash of the latest view change.
    pub fn latest_hash(&self) -> HashOf<Proof> {
        self.proofs
            .last()
            .map_or(EmptyChainHash::default().into(), Proof::hash)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    use iroha_crypto::{Hash, HashOf};

    use super::*;

    #[test]
    fn proof_is_valid() -> Result<()> {
        let key_pair_1 = KeyPair::generate()?;
        let key_pair_2 = KeyPair::generate()?;
        let proof = Proof::commit_timeout(
            HashOf::from_hash(Hash([1_u8; 32])),
            HashOf::from_hash(Hash([2_u8; 32])),
            HashOf::from_hash(Hash([3_u8; 32])),
            key_pair_1.clone(),
        )?
        .sign(key_pair_2.clone())?;
        let peer_1 = PeerId::new("127.0.0.1:1001", &key_pair_1.public_key);
        let peer_2 = PeerId::new("127.0.0.1:1002", &key_pair_2.public_key);
        let peers = [peer_1, peer_2].into();
        assert!(proof.verify(&peers, 1));
        Ok(())
    }

    #[test]
    fn proof_has_not_enough_signatures() -> Result<()> {
        let key_pair_1 = KeyPair::generate()?;
        let key_pair_2 = KeyPair::generate()?;
        let proof = Proof::commit_timeout(
            HashOf::from_hash(Hash([1_u8; 32])),
            HashOf::from_hash(Hash([2_u8; 32])),
            HashOf::from_hash(Hash([3_u8; 32])),
            key_pair_1.clone(),
        )?;
        let peer_1 = PeerId::new("127.0.0.1:1001", &key_pair_1.public_key);
        let peer_2 = PeerId::new("127.0.0.1:1002", &key_pair_2.public_key);
        let peers = [peer_1, peer_2].into();
        assert!(!proof.verify(&peers, 1));
        Ok(())
    }

    #[test]
    fn proof_has_not_enough_valid_signatures() -> Result<()> {
        let key_pair_1 = KeyPair::generate()?;
        let key_pair_2 = KeyPair::generate()?;
        let key_pair_3 = KeyPair::generate()?;
        let proof = Proof::commit_timeout(
            HashOf::from_hash(Hash([1_u8; 32])),
            HashOf::from_hash(Hash([2_u8; 32])),
            HashOf::from_hash(Hash([3_u8; 32])),
            key_pair_1.clone(),
        )?
        .sign(key_pair_3)?;
        let peer_1 = PeerId::new("127.0.0.1:1001", &key_pair_1.public_key);
        let peer_2 = PeerId::new("127.0.0.1:1002", &key_pair_2.public_key);
        let peers = [peer_1, peer_2].into();
        assert!(!proof.verify(&peers, 1));
        Ok(())
    }

    #[test]
    fn proof_chain_is_valid() -> Result<()> {
        let mut proof_chain = ProofChain::empty();
        let key_pair_1 = KeyPair::generate()?;
        let key_pair_2 = KeyPair::generate()?;
        let peer_1 = PeerId::new("127.0.0.1:1001", &key_pair_1.public_key);
        let peer_2 = PeerId::new("127.0.0.1:1002", &key_pair_2.public_key);
        let latest_block = HashOf::from_hash(Hash([3_u8; 32]));
        for i in 0..10 {
            let proof = Proof::commit_timeout(
                HashOf::from_hash(Hash([i; 32])),
                proof_chain.latest_hash(),
                latest_block,
                key_pair_1.clone(),
            )?
            .sign(key_pair_2.clone())?;
            proof_chain.push(proof);
        }
        let peers = [peer_1, peer_2].into();
        assert!(proof_chain.verify_with_state(&peers, 1, &latest_block));
        Ok(())
    }

    #[test]
    fn proof_chain_is_not_valid() -> Result<()> {
        let mut proof_chain = ProofChain::empty();
        let key_pair_1 = KeyPair::generate()?;
        let key_pair_2 = KeyPair::generate()?;
        let peer_1 = PeerId::new("127.0.0.1:1001", &key_pair_1.public_key);
        let peer_2 = PeerId::new("127.0.0.1:1002", &key_pair_2.public_key);
        let latest_block = HashOf::from_hash(Hash([3_u8; 32]));
        for i in 0..10 {
            let latest_proof_hash = if i == 2 {
                HashOf::from_hash(Hash([0_u8; 32]))
            } else {
                proof_chain.latest_hash()
            };
            let proof = Proof::commit_timeout(
                HashOf::from_hash(Hash([i; 32])),
                latest_proof_hash,
                latest_block,
                key_pair_1.clone(),
            )?
            .sign(key_pair_2.clone())?;
            proof_chain.push(proof);
        }
        let peers = [peer_1, peer_2].into();
        assert!(!proof_chain.verify_with_state(&peers, 1, &latest_block));
        Ok(())
    }
}
