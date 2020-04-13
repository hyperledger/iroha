use crate::prelude::*;
use iroha_derive::Io;
use parity_scale_codec::{Decode, Encode};
use std::time::SystemTime;

/// An ordered set of instructions, which is applied to the ledger atomically.
#[derive(Clone, Debug, Io, Encode, Decode)]
pub enum Transaction {
    Requested {
        /// An ordered set of instructions.
        instructions: Vec<Contract>,
        /// Time of creation (unix time, in milliseconds).
        creation_time: u128,
        /// Account ID of transaction creator (username@domain).
        account_id: Id,
        signatures: Vec<Signature>,
    },
    Accepted {
        /// An ordered set of instructions.
        instructions: Vec<Contract>,
        /// Time of creation (unix time, in milliseconds).
        creation_time: u128,
        /// Account ID of transaction creator (username@domain).
        account_id: Id,
        signatures: Vec<Signature>,
    },
    Signed {
        /// An ordered set of instructions.
        instructions: Vec<Contract>,
        /// Time of creation (unix time, in milliseconds).
        creation_time: u128,
        /// Account ID of transaction creator (username@domain).
        account_id: Id,
        signatures: Vec<Signature>,
    },
    Valid {
        /// An ordered set of instructions.
        instructions: Vec<Contract>,
        /// Time of creation (unix time, in milliseconds).
        creation_time: u128,
        /// Account ID of transaction creator (username@domain).
        account_id: Id,
        signatures: Vec<Signature>,
    },
}

impl Transaction {
    pub fn builder(instructions: Vec<Contract>, account_id: Id) -> TxBuilder {
        TxBuilder {
            instructions,
            account_id,
            creation_time: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("Failed to get System Time.")
                .as_millis(),
            signatures: Option::None,
        }
    }

    pub fn accept(self) -> Result<Transaction, String> {
        if let Transaction::Requested {
            instructions,
            creation_time,
            account_id,
            signatures,
        } = self
        {
            Ok(Transaction::Accepted {
                instructions,
                creation_time,
                account_id,
                signatures,
            })
        } else {
            Err("Transaction should be in Requested state to be accepted.".to_string())
        }
    }

    pub fn sign(self, new_signatures: Vec<Signature>) -> Result<Transaction, String> {
        if let Transaction::Accepted {
            instructions,
            creation_time,
            account_id,
            signatures,
        } = self
        {
            Ok(Transaction::Signed {
                signatures: vec![signatures, new_signatures]
                    .into_iter()
                    .flatten()
                    .collect(),
                instructions,
                creation_time,
                account_id,
            })
        } else {
            Err("Transaction should be in Accepted state to be signed.".to_string())
        }
    }

    pub fn validate(self) -> Result<Transaction, String> {
        if let Transaction::Signed {
            instructions,
            creation_time,
            account_id,
            signatures,
        } = self
        {
            Ok(Transaction::Valid {
                instructions,
                creation_time,
                account_id,
                signatures,
            })
        } else {
            Err("Transaction should be in Signed state to be validated.".to_string())
        }
    }

    pub fn hash(&self) -> Hash {
        use ursa::blake2::{
            digest::{Input, VariableOutput},
            VarBlake2b,
        };
        let bytes: Vec<u8> = self.into();
        let vec_hash = VarBlake2b::new(32)
            .expect("Failed to initialize variable size hash")
            .chain(bytes)
            .vec_result();
        let mut hash = [0; 32];
        hash.copy_from_slice(&vec_hash);
        hash
    }
}

/// Builder struct for `Transaction`.
pub struct TxBuilder {
    pub instructions: Vec<Contract>,
    pub creation_time: u128,
    pub account_id: Id,
    pub signatures: Option<Vec<Signature>>,
}

impl TxBuilder {
    pub fn build(self) -> Transaction {
        Transaction::Requested {
            instructions: self.instructions,
            creation_time: self.creation_time,
            account_id: self.account_id,
            signatures: self.signatures.unwrap_or_default(),
        }
    }
}
