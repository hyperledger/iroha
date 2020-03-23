use crate::{crypto::Signature, isi::Command};
use std::{
    fmt::{Debug, Display, Formatter},
    time::SystemTime,
};

/// An ordered set of instructions, which is applied to the ledger atomically.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Transaction {
    /// An ordered set of instructions.
    //TODO: think about constructor with `Into<Command>` parameter signature.
    pub instructions: Vec<Command>,
    /// Time of creation (unix time, in milliseconds).
    creation_time: u128,
    /// Account ID of transaction creator (username@domain).
    pub account_id: String,
    /// Quorum field (indicates required number of signatures).
    quorum: u32, //TODO: this will almost certainly change; accounts need conditional multisig based on some rules, not associated with a transaction
    pub signatures: Vec<Signature>,
}

impl Transaction {
    pub fn builder(instructions: Vec<Command>, account_id: String) -> TxBuilder {
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

/// # Example
/// ```
/// use iroha::prelude::*;
///
/// let tx_payload = &Transaction::builder(Vec::new(),"account@domain".to_string())
///     .build();
/// let result: Vec<u8> = tx_payload.into();
/// ```
impl std::convert::From<&Transaction> for Vec<u8> {
    fn from(tx_payload: &Transaction) -> Self {
        bincode::serialize(tx_payload).expect("Failed to serialize payload.")
    }
}

/// # Example
/// ```
/// # use iroha::prelude::*;
///
/// # let tx_payload = &Transaction::builder(Vec::new(),"account@domain".to_string())
/// #     .build();
/// # let result: Vec<u8> = tx_payload.into();
/// let tx_payload: Transaction = result.into();
/// ```
impl std::convert::From<Vec<u8>> for Transaction {
    fn from(tx_payload: Vec<u8>) -> Self {
        bincode::deserialize(&tx_payload).expect("Failed to deserialize payload.")
    }
}

/// Builder struct for `Transaction`.
#[derive(Default)]
pub struct TxBuilder {
    pub instructions: Vec<Command>,
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

impl Display for Transaction {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{:}", self.account_id) //TODO: implement
    }
}

impl Debug for Transaction {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{:}", self.account_id) //TODO: implement
    }
}
