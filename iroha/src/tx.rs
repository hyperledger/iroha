//! This module contains Transaction related functionality of the Iroha.
//!
//! `Transaction` is the start of the Transaction lifecycle.

use crate::prelude::*;
use iroha_crypto::KeyPair;
use iroha_derive::Io;
use parity_scale_codec::{Decode, Encode};
use std::{
    cmp::min,
    time::{Duration, SystemTime},
};

/// This structure represents transaction right after construction.
#[derive(Clone, Debug, Io, Encode, Decode)]
pub struct Transaction {
    payload: Payload,
    /// Signatures of accounts. There can be multiple in case of MST.
    signatures: Vec<Signature>,
}

#[derive(Clone, Debug, Io, Encode, Decode)]
struct Payload {
    /// Account ID of transaction creator.
    account_id: <Account as Identifiable>::Id,
    /// An ordered set of instructions.
    instructions: Vec<Instruction>,
    /// Time of creation (unix time, in milliseconds).
    creation_time: u64,
    /// The transaction will be dropped after this time if it is still in a `Queue`.
    time_to_live_ms: u64,
}

impl Transaction {
    /// Default `CreatedTransaction` constructor.
    pub fn new(
        instructions: Vec<Instruction>,
        account_id: <Account as Identifiable>::Id,
        proposed_ttl_ms: u64,
    ) -> Transaction {
        Transaction {
            payload: Payload {
                instructions,
                account_id,
                creation_time: SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .expect("Failed to get System Time.")
                    .as_millis() as u64,
                time_to_live_ms: proposed_ttl_ms,
            },
            signatures: Vec::new(),
        }
    }

    /// Sign transaction with the provided key pair.
    ///
    /// Returns `Ok(SignedTransaction)` if succeeded and `Err(String)` if failed.
    pub fn sign(self, key_pair: &KeyPair) -> Result<SignedTransaction, String> {
        let mut signatures = self.signatures.clone();
        signatures.push(Signature::new(key_pair.clone(), &self.hash())?);
        Ok(SignedTransaction {
            payload: self.payload,
            signatures,
        })
    }

    /// Calculate transaction `Hash`.
    pub fn hash(&self) -> Hash {
        use ursa::blake2::{
            digest::{Input, VariableOutput},
            VarBlake2b,
        };
        let bytes: Vec<u8> = self.payload.clone().into();
        let vec_hash = VarBlake2b::new(32)
            .expect("Failed to initialize variable size hash")
            .chain(bytes)
            .vec_result();
        let mut hash = [0; 32];
        hash.copy_from_slice(&vec_hash);
        hash
    }
}

/// `SignedTransaction` represents transaction signed by corresponding initiator's account.
#[derive(Clone, Debug, Io, Encode, Decode)]
pub struct SignedTransaction {
    payload: Payload,
    /// Signatures of accounts. There can be multiple in case of MST.
    signatures: Vec<Signature>,
}

impl SignedTransaction {
    /// Sign transaction with the provided key pair.
    ///
    /// Returns `Ok(SignedTransaction)` if succeeded and `Err(String)` if failed.
    pub fn sign(self, key_pair: &KeyPair) -> Result<SignedTransaction, String> {
        let mut signatures = self.signatures.clone();
        signatures.push(Signature::new(key_pair.clone(), &self.hash())?);
        Ok(SignedTransaction {
            payload: self.payload,
            signatures,
        })
    }

    /// Transaction acceptance will check that transaction signatures are valid and move state one
    /// step forward.
    ///
    /// Returns `Ok(AcceptedTransaction)` if succeeded and `Err(String)` if failed.
    pub fn accept(self) -> Result<AcceptedTransaction, String> {
        for signature in &self.signatures {
            if let Err(e) = signature.verify(&self.hash()) {
                return Err(format!("Failed to verify signatures: {}", e));
            }
        }
        Ok(AcceptedTransaction {
            payload: self.payload,
            signatures: self.signatures,
        })
    }

    /// Calculate transaction `Hash`.
    pub fn hash(&self) -> Hash {
        use ursa::blake2::{
            digest::{Input, VariableOutput},
            VarBlake2b,
        };
        let bytes: Vec<u8> = self.payload.clone().into();
        let vec_hash = VarBlake2b::new(32)
            .expect("Failed to initialize variable size hash")
            .chain(bytes)
            .vec_result();
        let mut hash = [0; 32];
        hash.copy_from_slice(&vec_hash);
        hash
    }
}

/// `AcceptedTransaction` represents a transaction accepted by iroha peer.
#[derive(Clone, Debug, Io, Encode, Decode)]
pub struct AcceptedTransaction {
    payload: Payload,
    signatures: Vec<Signature>,
}

impl AcceptedTransaction {
    /// Calculate transaction `Hash`.
    pub fn hash(&self) -> Hash {
        use ursa::blake2::{
            digest::{Input, VariableOutput},
            VarBlake2b,
        };
        let bytes: Vec<u8> = self.payload.clone().into();
        let vec_hash = VarBlake2b::new(32)
            .expect("Failed to initialize variable size hash")
            .chain(bytes)
            .vec_result();
        let mut hash = [0; 32];
        hash.copy_from_slice(&vec_hash);
        hash
    }

    /// Checks if this transaction is waiting longer than specified in `transaction_time_to_live` from `QueueConfiguration` or `time_to_live_ms` of this transaction.
    /// Meaning that the transaction will be expired as soon as the lesser of the specified TTLs was reached.
    pub fn is_expired(&self, transaction_time_to_live: Duration) -> bool {
        let current_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Failed to get System Time.");
        (current_time - Duration::from_millis(self.payload.creation_time))
            > min(
                Duration::from_millis(self.payload.time_to_live_ms),
                transaction_time_to_live,
            )
    }

    /// Move transaction lifecycle forward by checking an ability to apply instructions to the
    /// `WorldStateView`.
    ///
    /// Returns `Ok(ValidTransaction)` if succeeded and `Err(String)` if failed.
    pub fn validate(
        self,
        world_state_view: &mut WorldStateView,
    ) -> Result<ValidTransaction, String> {
        let mut world_state_view_temp = world_state_view.clone();
        let account_id = self.payload.account_id.clone();
        world_state_view
            .read_account(&account_id)
            .ok_or(format!("Account with id {} not found", account_id))?
            .verify_signature(
                self.signatures.first().ok_or("No signatures found.")?,
                &self.hash(),
            )?;
        for instruction in &self.payload.instructions {
            world_state_view_temp = instruction
                .execute(self.payload.account_id.clone(), &world_state_view_temp)?
                .world_state_view;
        }
        *world_state_view = world_state_view_temp;
        Ok(ValidTransaction {
            payload: self.payload,
            signatures: self.signatures,
        })
    }
}

/// `ValidTransaction` represents trustfull Transaction state.
#[derive(Clone, Debug, Io, Encode, Decode)]
pub struct ValidTransaction {
    payload: Payload,
    signatures: Vec<Signature>,
}

impl ValidTransaction {
    // TODO: Should not be in `ValidTransaction`.
    /// Move transaction lifecycle forward by checking an ability to apply instructions to the
    /// `WorldStateView`.
    ///
    /// Returns `Ok(ValidTransaction)` if succeeded and `Err(String)` if failed.
    pub fn validate(
        self,
        world_state_view: &mut WorldStateView,
    ) -> Result<ValidTransaction, String> {
        let mut world_state_view_temp = world_state_view.clone();
        let account_id = self.payload.account_id.clone();
        world_state_view
            .read_account(&account_id)
            .ok_or(format!("Account with id {} not found", account_id))?
            .verify_signature(
                self.signatures.first().ok_or("No signatures found.")?,
                &self.hash(),
            )?;
        for instruction in &self.payload.instructions {
            world_state_view_temp = instruction
                .execute(account_id.clone(), &world_state_view_temp)?
                .world_state_view;
        }
        *world_state_view = world_state_view_temp;
        Ok(ValidTransaction {
            payload: self.payload,
            signatures: self.signatures,
        })
    }

    /// Apply instructions to the `WorldStateView`.
    pub fn proceed(&self, world_state_view: &mut WorldStateView) -> Result<(), String> {
        let mut world_state_view_temp = world_state_view.clone();
        for instruction in &self.payload.instructions {
            world_state_view_temp = instruction
                .execute(self.payload.account_id.clone(), &world_state_view_temp)?
                .world_state_view;
        }
        *world_state_view = world_state_view_temp;
        Ok(())
    }

    /// Calculate transaction `Hash`.
    pub fn hash(&self) -> Hash {
        use ursa::blake2::{
            digest::{Input, VariableOutput},
            VarBlake2b,
        };
        let bytes: Vec<u8> = self.payload.clone().into();
        let vec_hash = VarBlake2b::new(32)
            .expect("Failed to initialize variable size hash")
            .chain(bytes)
            .vec_result();
        let mut hash = [0; 32];
        hash.copy_from_slice(&vec_hash);
        hash
    }
}

impl From<&AcceptedTransaction> for SignedTransaction {
    fn from(transaction: &AcceptedTransaction) -> SignedTransaction {
        let transaction = transaction.clone();
        SignedTransaction {
            payload: transaction.payload,
            signatures: transaction.signatures,
        }
    }
}

mod event {
    use super::*;
    use crate::event::{Entity, Occurrence};

    impl From<&SignedTransaction> for Occurrence {
        fn from(transaction: &SignedTransaction) -> Occurrence {
            Occurrence::Created(Entity::Transaction(transaction.into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init::{self, config::InitConfiguration};

    #[test]
    fn hash_should_be_the_same() {
        let tx = Transaction::new(vec![], AccountId::new("root", "global"), 1000);
        let tx_hash = tx.hash();
        let root_key_pair = &KeyPair::generate().expect("Failed to generate key pair.");
        let signed_tx = tx.sign(&root_key_pair).expect("Failed to sign.");
        let signed_tx_hash = signed_tx.hash();
        let accepted_tx = signed_tx.accept().expect("Failed to accept.");
        let accepted_tx_hash = accepted_tx.hash();
        let valid_tx_hash = accepted_tx
            .validate(&mut WorldStateView::new(Peer::with_domains(
                PeerId {
                    address: "127.0.0.1:8080".to_string(),
                    public_key: KeyPair::generate()
                        .expect("Failed to generate KeyPair.")
                        .public_key,
                },
                &Vec::new(),
                init::domains(&InitConfiguration {
                    root_public_key: root_key_pair.public_key.clone(),
                }),
            )))
            .expect("Failed to validate.")
            .hash();
        assert_eq!(tx_hash, signed_tx_hash);
        assert_eq!(tx_hash, accepted_tx_hash);
        assert_eq!(tx_hash, valid_tx_hash);
    }
}
