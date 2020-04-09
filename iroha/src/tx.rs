use crate::{crypto::Signature, isi::Contract};
use iroha_derive::Io;
use parity_scale_codec::{Decode, Encode};
use std::time::SystemTime;

/// An ordered set of instructions, which is applied to the ledger atomically.
#[derive(Clone, Debug, Io, Encode, Decode)]
pub struct Transaction {
    /// An ordered set of instructions.
    //TODO: think about constructor with `Into<Contract>` parameter signature.
    pub instructions: Vec<Contract>,
    /// Time of creation (unix time, in milliseconds).
    creation_time: u128,
    /// Account ID of transaction creator (username@domain).
    pub account_id: String,
    /// Quorum field (indicates required number of signatures).
    quorum: u32, //TODO: this will almost certainly change; accounts need conditional multisig based on some rules, not associated with a transaction
    pub signatures: Vec<Signature>,
}

impl Transaction {
    pub fn builder(instructions: Vec<Contract>, account_id: String) -> TxBuilder {
        TxBuilder {
            instructions,
            account_id,
            creation_time: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("Failed to get System Time.")
                .as_millis(),
            ..Default::default()
        }
    }

    //TODO: make Transaction an Enum and return Transaction::Valid
    pub fn validate(self) -> Result<Transaction, ()> {
        Ok(self)
    }
}

/// Builder struct for `Transaction`.
#[derive(Default)]
pub struct TxBuilder {
    pub instructions: Vec<Contract>,
    pub creation_time: u128,
    pub account_id: String,
    pub quorum: Option<u32>,
    pub signatures: Option<Vec<Signature>>,
}

impl TxBuilder {
    pub fn build(self) -> Transaction {
        Transaction {
            instructions: self.instructions,
            creation_time: self.creation_time,
            account_id: self.account_id,
            quorum: self.quorum.unwrap_or(1),
            signatures: self.signatures.unwrap_or_default(),
        }
    }
}
