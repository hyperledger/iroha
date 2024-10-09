//! Structures related to proofs and reasons of view changes.
//! Where view change is a process of changing topology due to some faulty network behavior.

use std::collections::{btree_map::Entry, BTreeMap};

use eyre::Result;
use indexmap::IndexSet;
use iroha_crypto::{HashOf, PublicKey, SignatureOf};
use iroha_data_model::block::BlockHeader;
use parity_scale_codec::{Decode, Encode};
use thiserror::Error;

use super::network_topology::Topology;

type ViewChangeProofSignature = (PublicKey, SignatureOf<ViewChangeProofPayload>);

/// Error emerge during insertion of `Proof` into `ProofChain`
#[derive(Error, displaydoc::Display, Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum Error {
    /// Block hash of proof doesn't match hash of proof chain
    BlockHashMismatch,
    /// Peer already have verified view change proof with index larger than received
    ViewChangeOutdated,
}

#[derive(Debug, Clone, Decode, Encode)]
struct ViewChangeProofPayload {
    /// Hash of the latest committed block.
    latest_block: HashOf<BlockHeader>,
    /// Within a round, what is the index of the view change this proof is trying to prove.
    view_change_index: u32,
}

/// The proof of a view change. It needs to be signed by f+1 peers for proof to be valid and view change to happen.
#[derive(Debug, Clone, Encode)]
pub struct SignedViewChangeProof {
    signatures: Vec<ViewChangeProofSignature>,
    payload: ViewChangeProofPayload,
}

/// Builder for proofs
#[repr(transparent)]
pub struct ProofBuilder(SignedViewChangeProof);

impl ProofBuilder {
    /// Constructor from index.
    pub fn new(latest_block: HashOf<BlockHeader>, view_change_index: usize) -> Self {
        let view_change_index = view_change_index
            .try_into()
            .expect("INTERNAL BUG: Blockchain height should fit into usize");

        let proof = SignedViewChangeProof {
            payload: ViewChangeProofPayload {
                latest_block,
                view_change_index,
            },
            signatures: Vec::new(),
        };

        Self(proof)
    }

    /// Sign this message with the peer's private key.
    pub fn sign(mut self, key_pair: &iroha_crypto::KeyPair) -> SignedViewChangeProof {
        let signature = SignatureOf::new(key_pair.private_key(), &self.0.payload);
        self.0.signatures = vec![(key_pair.public_key().clone(), signature)];
        self.0
    }
}

impl SignedViewChangeProof {
    /// Verify the signatures of `other` and add them to this proof.
    /// Return number of new signatures added.
    fn merge_signatures(
        &mut self,
        other: Vec<ViewChangeProofSignature>,
        topology: &Topology,
    ) -> usize {
        let len_before = self.signatures.len();

        let signatures = core::mem::take(&mut self.signatures)
            .into_iter()
            .collect::<IndexSet<_>>();

        self.signatures = other
            .into_iter()
            .fold(signatures, |mut acc, (public_key, signature)| {
                if topology.position(&public_key).is_some() {
                    acc.insert((public_key, signature));
                }

                acc
            })
            .into_iter()
            .collect();

        let len_after = self.signatures.len();

        len_after - len_before
    }

    /// Verify if the proof is valid, given the peers in `topology`.
    fn verify(&self, topology: &Topology) -> bool {
        let valid_count = self
            .signatures
            .iter()
            .filter(|&(public_key, _)| topology.position(public_key).is_some())
            .count();

        // NOTE: See Whitepaper for the information on this limit.
        valid_count > topology.max_faults()
    }
}

/// Structure representing view change proofs collected by the peer.
/// All proofs are attributed to the same block.
#[derive(Debug, Clone, Default)]
pub struct ProofChain(BTreeMap<u32, SignedViewChangeProof>);

impl ProofChain {
    /// Find next index to last verified view change proof.
    /// Proof is verified if it has more or qual ot f + 1 valid signatures.
    pub fn verify_with_state(
        &self,
        topology: &Topology,
        latest_block: HashOf<BlockHeader>,
    ) -> usize {
        self.0
            .iter()
            .rev()
            .filter(|(_, proof)| proof.payload.latest_block == latest_block)
            .find(|(_, proof)| proof.verify(topology))
            .map_or(0, |(view_change_index, _)| {
                (*view_change_index as usize) + 1
            })
    }

    /// Prune proofs leave only proofs for specified latest block
    pub fn prune(&mut self, latest_block: HashOf<BlockHeader>) {
        self.0
            .retain(|_, proof| proof.payload.latest_block == latest_block)
    }

    /// Attempt to insert a view chain proof into this `ProofChain`.
    ///
    /// # Errors
    /// - If proof latest block hash doesn't match peer latest block hash
    /// - If proof view change number lower than current verified view change
    pub fn insert_proof(
        &mut self,
        new_proof: SignedViewChangeProof,
        topology: &Topology,
        latest_block: HashOf<BlockHeader>,
    ) -> Result<(), Error> {
        if new_proof.payload.latest_block != latest_block {
            return Err(Error::BlockHashMismatch);
        }
        let next_unfinished_view_change = self.verify_with_state(topology, latest_block);
        let new_proof_view_change_index = new_proof.payload.view_change_index as usize;
        if new_proof_view_change_index + 1 < next_unfinished_view_change {
            return Err(Error::ViewChangeOutdated); // We only care about current proof and proof which might happen in the future
        }
        if new_proof_view_change_index + 1 == next_unfinished_view_change {
            return Ok(()); // Received a proof for already verified latest proof, not an error just nothing to do about
        }

        match self.0.entry(new_proof.payload.view_change_index) {
            Entry::Occupied(mut occupied) => {
                occupied
                    .get_mut()
                    .merge_signatures(new_proof.signatures, topology);
            }
            Entry::Vacant(vacant) => {
                vacant.insert(new_proof);
            }
        }

        Ok(())
    }

    /// Get proof for requested view change index
    pub fn get_proof_for_view_change(
        &self,
        view_change_index: usize,
    ) -> Option<SignedViewChangeProof> {
        #[allow(clippy::cast_possible_truncation)]
        // Was created from u32 so should be able to cast back
        self.0.get(&(view_change_index as u32)).cloned()
    }
}

mod candidate {
    use indexmap::IndexSet;
    use parity_scale_codec::Input;

    use super::*;

    #[derive(Decode)]
    struct SignedProofCandidate {
        signatures: Vec<ViewChangeProofSignature>,
        payload: ViewChangeProofPayload,
    }

    impl SignedProofCandidate {
        fn validate(self) -> Result<SignedViewChangeProof, &'static str> {
            self.validate_signatures()?;

            Ok(SignedViewChangeProof {
                signatures: self.signatures,
                payload: self.payload,
            })
        }

        fn validate_signatures(&self) -> Result<(), &'static str> {
            if self.signatures.is_empty() {
                return Err("Proof missing signatures");
            }

            self.signatures
                .iter()
                .map(|signature| &signature.0)
                .try_fold(IndexSet::new(), |mut acc, elem| {
                    if !acc.insert(elem) {
                        return Err("Duplicate signature");
                    }

                    Ok(acc)
                })?;

            self.signatures
                .iter()
                .try_for_each(|(public_key, payload)| {
                    payload
                        .verify(public_key, &self.payload)
                        .map_err(|_| "Invalid signature")
                })?;

            Ok(())
        }
    }

    impl Decode for SignedViewChangeProof {
        fn decode<I: Input>(input: &mut I) -> Result<Self, parity_scale_codec::Error> {
            SignedProofCandidate::decode(input)?
                .validate()
                .map_err(Into::into)
        }
    }
}

#[cfg(test)]
mod tests {
    use iroha_crypto::{Hash, HashOf, KeyPair};

    use super::*;
    use crate::sumeragi::network_topology::test_topology_with_keys;

    fn key_pairs<const N: usize>() -> [KeyPair; N] {
        [(); N].map(|()| KeyPair::random())
    }

    fn prepare_data<const N: usize>() -> ([KeyPair; N], Topology, HashOf<BlockHeader>) {
        let key_pairs = key_pairs::<N>();
        let topology = test_topology_with_keys(&key_pairs);
        let latest_block = HashOf::from_untyped_unchecked(Hash::prehashed([0; 32]));

        (key_pairs, topology, latest_block)
    }

    fn create_signed_payload(
        payload: ViewChangeProofPayload,
        signatories: &[KeyPair],
    ) -> SignedViewChangeProof {
        let signatures = signatories
            .iter()
            .map(|key_pair| {
                (
                    key_pair.public_key().clone(),
                    SignatureOf::new(key_pair.private_key(), &payload),
                )
            })
            .collect();
        SignedViewChangeProof {
            signatures,
            payload,
        }
    }

    #[test]
    fn verify_with_state_on_empty() {
        let (_key_pairs, topology, latest_block) = prepare_data::<10>();
        let chain = ProofChain::default();

        assert_eq!(chain.verify_with_state(&topology, latest_block), 0);
    }

    #[test]
    fn verify_with_state() {
        let (key_pairs, topology, latest_block) = prepare_data::<10>();

        let len = 10;

        let mut view_change_payloads = (0..).map(|view_change_index| ViewChangeProofPayload {
            latest_block,
            view_change_index,
        });

        let complete_proofs = (&mut view_change_payloads)
            .take(len)
            .map(|payload| create_signed_payload(payload, &key_pairs[..=topology.max_faults()]))
            .collect::<Vec<_>>();

        let incomplete_proofs = (&mut view_change_payloads)
            .take(len)
            .map(|payload| create_signed_payload(payload, &key_pairs[..1]))
            .collect::<Vec<_>>();

        let proofs = {
            let mut proofs = complete_proofs;
            proofs.extend(incomplete_proofs);
            proofs
        };
        let chain = ProofChain(
            proofs
                .clone()
                .into_iter()
                .map(|proof| (proof.payload.view_change_index, proof))
                .collect(),
        );

        // verify_with_state equal to view_change_index of last verified proof plus 1
        assert_eq!(chain.verify_with_state(&topology, latest_block), len);

        // Add complete proofs on top to check that verified view change is updated as well
        let complete_proofs = (&mut view_change_payloads)
            .take(len)
            .map(|payload| create_signed_payload(payload, &key_pairs[..=topology.max_faults()]))
            .collect::<Vec<_>>();

        let proofs = {
            let mut proofs = proofs;
            proofs.extend(complete_proofs);
            proofs
        };
        let chain = ProofChain(
            proofs
                .clone()
                .into_iter()
                .map(|proof| (proof.payload.view_change_index, proof))
                .collect(),
        );
        assert_eq!(chain.verify_with_state(&topology, latest_block), 3 * len);
    }

    #[test]
    fn proof_for_invalid_block_is_rejected() {
        let (key_pairs, topology, latest_block) = prepare_data::<10>();

        let wrong_latest_block = HashOf::from_untyped_unchecked(Hash::prehashed([1; 32]));

        let mut me = ProofChain::default();
        let other = ProofBuilder::new(wrong_latest_block, 0).sign(&key_pairs[1]);

        assert_eq!(
            me.insert_proof(other, &topology, latest_block),
            Err(Error::BlockHashMismatch)
        );
    }

    #[test]
    fn proof_from_the_past_is_rejected() {
        let (key_pairs, topology, latest_block) = prepare_data::<10>();

        let mut chain = ProofChain::default();

        let proof_future = create_signed_payload(
            ViewChangeProofPayload {
                latest_block,
                view_change_index: 10,
            },
            &key_pairs,
        );

        assert_eq!(
            Ok(()),
            chain.insert_proof(proof_future, &topology, latest_block)
        );
        assert_eq!(chain.verify_with_state(&topology, latest_block), 11);

        let proof = create_signed_payload(
            ViewChangeProofPayload {
                latest_block,
                view_change_index: 1,
            },
            &key_pairs,
        );

        assert_eq!(
            Err(Error::ViewChangeOutdated),
            chain.insert_proof(proof, &topology, latest_block)
        );
        assert_eq!(chain.verify_with_state(&topology, latest_block), 11);
    }

    #[test]
    fn proofs_are_merged() {
        let (key_pairs, topology, latest_block) = prepare_data::<10>();

        let mut chain = ProofChain::default();

        let (from, to) = (topology.max_faults() / 2, topology.max_faults() + 1);
        let payload = ViewChangeProofPayload {
            latest_block,
            view_change_index: 0,
        };

        let proof_0_part_1 = create_signed_payload(payload.clone(), &key_pairs[..from]);

        assert_eq!(
            Ok(()),
            chain.insert_proof(proof_0_part_1, &topology, latest_block)
        );
        assert_eq!(chain.verify_with_state(&topology, latest_block), 0);

        let proof_0_part_2 = create_signed_payload(payload, &key_pairs[from..to]);

        assert_eq!(
            Ok(()),
            chain.insert_proof(proof_0_part_2, &topology, latest_block)
        );
        assert_eq!(chain.verify_with_state(&topology, latest_block), 1);
    }

    #[test]
    fn proofs_are_appended() {
        let (key_pairs, topology, latest_block) = prepare_data::<10>();

        let mut chain = ProofChain::default();

        let proof_0 = create_signed_payload(
            ViewChangeProofPayload {
                latest_block,
                view_change_index: 0,
            },
            &key_pairs,
        );

        assert_eq!(Ok(()), chain.insert_proof(proof_0, &topology, latest_block));
        assert_eq!(chain.verify_with_state(&topology, latest_block), 1);

        let proof_1 = create_signed_payload(
            ViewChangeProofPayload {
                latest_block,
                view_change_index: 1,
            },
            &key_pairs,
        );

        assert_eq!(Ok(()), chain.insert_proof(proof_1, &topology, latest_block));
        assert_eq!(chain.verify_with_state(&topology, latest_block), 2);
    }
}
