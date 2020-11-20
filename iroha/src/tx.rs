//! This module contains Transaction related functionality of the Iroha.
//!
//! `Transaction` is the start of the Transaction lifecycle.

use crate::{isi::Execute, prelude::*};
use iroha_data_model::prelude::*;
use iroha_derive::Io;
use parity_scale_codec::{Decode, Encode};
use std::{
    cmp::min,
    time::{Duration, SystemTime},
};

/// Temp trait for transaction acceptance.
//TODO: replace with From.
pub trait Accept {
    /// Transform transaction to `AcceptedTransaction`.
    fn accept(self) -> Result<AcceptedTransaction, String>;
}

impl Accept for Transaction {
    /// Transaction acceptance will check that transaction signatures are valid and move state one
    /// step forward.
    ///
    /// Returns `Ok(AcceptedTransaction)` if succeeded and `Err(String)` if failed.
    fn accept(self) -> Result<AcceptedTransaction, String> {
        for signature in &self.signatures {
            if let Err(e) = signature.verify(self.hash().as_ref()) {
                return Err(format!("Failed to verify signatures: {}", e));
            }
        }
        Ok(AcceptedTransaction {
            payload: self.payload,
            signatures: self.signatures,
        })
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
        let bytes: Vec<u8> = self.payload.clone().into();
        Hash::new(&bytes)
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
    pub fn validate(self, world_state_view: &WorldStateView) -> Result<ValidTransaction, String> {
        let mut world_state_view_temp = world_state_view.clone();
        let account_id = self.payload.account_id.clone();
        world_state_view
            .read_account(&account_id)
            .ok_or(format!("Account with id {} not found", account_id))?
            .verify_signature(
                self.signatures.first().ok_or("No signatures found.")?,
                self.hash().as_ref(),
            )?;
        for instruction in &self.payload.instructions {
            world_state_view_temp = instruction
                .clone()
                .execute(self.payload.account_id.clone(), &world_state_view_temp)?;
        }
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
    pub fn validate(self, world_state_view: &WorldStateView) -> Result<ValidTransaction, String> {
        let mut world_state_view_temp = world_state_view.clone();
        let account_id = self.payload.account_id.clone();
        world_state_view
            .read_account(&account_id)
            .ok_or(format!("Account with id {} not found", account_id))?
            .verify_signature(
                self.signatures.first().ok_or("No signatures found.")?,
                self.hash().as_ref(),
            )?;
        for instruction in &self.payload.instructions {
            world_state_view_temp = instruction
                .clone()
                .execute(self.payload.account_id.clone(), &world_state_view_temp)?;
        }
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
                .clone()
                .execute(self.payload.account_id.clone(), &world_state_view_temp)?;
        }
        *world_state_view = world_state_view_temp;
        Ok(())
    }

    /// Calculate transaction `Hash`.
    pub fn hash(&self) -> Hash {
        let bytes: Vec<u8> = self.payload.clone().into();
        Hash::new(&bytes)
    }
}

mod event {
    use super::*;
    use crate::event::{Entity, Occurrence};

    impl From<&Transaction> for Occurrence {
        fn from(transaction: &Transaction) -> Occurrence {
            Occurrence::Created(Entity::Transaction(transaction.into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init::{self, config::InitConfiguration};
    use std::collections::BTreeSet;

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
            .validate(&mut WorldStateView::new(Peer::with(
                PeerId {
                    address: "127.0.0.1:8080".to_string(),
                    public_key: KeyPair::generate()
                        .expect("Failed to generate KeyPair.")
                        .public_key,
                },
                init::domains(&InitConfiguration {
                    root_public_key: root_key_pair.public_key.clone(),
                }),
                BTreeSet::new(),
            )))
            .expect("Failed to validate.")
            .hash();
        assert_eq!(tx_hash, signed_tx_hash);
        assert_eq!(tx_hash, accepted_tx_hash);
        assert_eq!(tx_hash, valid_tx_hash);
    }
}
