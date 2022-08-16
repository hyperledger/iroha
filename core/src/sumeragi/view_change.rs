//! Structures related to proofs and reasons of view changes.
//! Where view change is a process of changing topology due to some faulty network behavior.
#![allow(
    clippy::arithmetic,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc
)]
use std::collections::HashSet;

use derive_more::Display;
use eyre::{Context, Result};
use iroha_crypto::{Hash, HashOf, KeyPair, PublicKey, Signature, SignatureOf, SignaturesOf};
use iroha_data_model::prelude::PeerId;
use iroha_macro::*;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};

use crate::block::{EmptyChainHash, VersionedCommittedBlock, VersionedValidBlock};

/// The proof of a view change. It needs to be signed by f+1 peers for proof to be valid and view change to happen.
#[derive(Debug, Clone, Decode, Encode, IntoSchema)]
pub struct Proof {
    pub latest_block_hash: HashOf<VersionedCommittedBlock>,
    pub view_change_index: u64,
    pub signatures: Vec<Signature>,
}

impl Proof {
    pub fn signature_payload(&self) -> Hash {
        let mut buf = [0_u8; Hash::LENGTH + std::mem::size_of::<u64>()];
        buf[..Hash::LENGTH].copy_from_slice(self.latest_block_hash.as_ref());
        buf[Hash::LENGTH..].copy_from_slice(&self.view_change_index.to_le_bytes());
        // Now we hash the buffer to produce a payload that is completely
        // different between view change proofs in the same sumeragi round.
        Hash::new(buf)
    }

    /// Signs this message with the peer's public and private key.
    /// This way peers vote for changing the view - changing the roles of peers.
    ///
    /// # Errors
    /// Can fail during creation of signature
    pub fn sign(&mut self, key_pair: KeyPair) -> Result<()> {
        let signature = Signature::new(key_pair, self.signature_payload().as_ref())?;
        self.signatures.push(signature);
        Ok(())
    }

    /// Verifies and adds signatures of other to this proof.
    pub fn merge_signatures(&mut self, other: &Vec<Signature>) {
        let signature_payload = self.signature_payload();
        for signature in other {
            if signature.verify(signature_payload.as_ref()).is_ok()
                && !self.signatures.contains(signature)
            {
                self.signatures.push(signature.clone());
            }
        }
    }

    /// Verify if the proof is valid, given the peers in `topology`.
    pub fn verify(&self, peers: &HashSet<PeerId>, max_faults: usize) -> bool {
        let peer_public_keys: HashSet<PublicKey> = peers
            .iter()
            .map(|peer_id| peer_id.public_key.clone())
            .collect();

        let mut valid_count = 0;
        let signature_payload = self.signature_payload();
        for signature in &self.signatures {
            if signature.verify(signature_payload.as_ref()).is_ok()
                && peer_public_keys.contains(signature.public_key())
            {
                valid_count += 1;
            }
        }

        // See Whitepaper for the information on this limit.
        #[allow(clippy::int_plus_one)]
        {
            valid_count >= max_faults + 1
        }
    }
}

pub trait ProofChain {
    /// Verify the view change proof chain.
    fn verify_with_state(
        &self,
        peers: &HashSet<PeerId>,
        max_faults: usize,
        latest_block: &HashOf<VersionedCommittedBlock>,
    ) -> usize;

    fn insert_proof(
        &mut self,
        peers: &HashSet<PeerId>,
        max_faults: usize,
        latest_block: &HashOf<VersionedCommittedBlock>,
        new_proof: &Proof,
    );
}

impl ProofChain for Vec<Proof> {
    fn verify_with_state(
        &self,
        peers: &HashSet<PeerId>,
        max_faults: usize,
        latest_block: &HashOf<VersionedCommittedBlock>,
    ) -> usize {
        let mut valid_view_change_counter = 0;
        for (i, proof) in self.iter().enumerate() {
            if proof.latest_block_hash != *latest_block {
                break;
            }
            if proof.view_change_index != (i as u64) {
                break;
            }
            if !proof.verify(peers, max_faults) {
                break;
            }
            valid_view_change_counter += 1;
        }
        valid_view_change_counter
    }

    fn insert_proof(
        &mut self,
        peers: &HashSet<PeerId>,
        max_faults: usize,
        latest_block: &HashOf<VersionedCommittedBlock>,
        new_proof: &Proof,
    ) {
        if new_proof.latest_block_hash != *latest_block {
            return;
        }
        let next_unfinished_view_change = self.verify_with_state(peers, max_faults, latest_block);
        if new_proof.view_change_index != (next_unfinished_view_change as u64) {
            return; // We only care about the current view change that may or may not happen.
        }
        self.truncate(next_unfinished_view_change + 1);
        if self.len() != next_unfinished_view_change + 1 {
            self.push(new_proof.clone());
        } else {
            self.last_mut()
                .expect("size must always be more than zero")
                .merge_signatures(&new_proof.signatures);
        }
    }
}
