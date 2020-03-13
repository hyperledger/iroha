use crate::model::{commands::oob::Command, crypto::Signature};
use std::fmt::{Debug, Display, Formatter, Result};

/// An ordered set of commands, which is applied to the ledger atomically.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Transaction {
    /// An ordered set of commands.
    //TODO: think about constructor with `Into<Command>` parameter signature.
    pub commands: Vec<Command>,
    /// Time of creation (unix time, in milliseconds).
    pub creation_time: u64,
    /// Account ID of transaction creator (username@domain).
    pub account_id: String,
    /// Quorum field (indicates required number of signatures).
    pub quorum: u32, //TODO: this will almost certainly change; accounts need conditional multisig based on some rules, not associated with a transaction
    pub signatures: Vec<Signature>,
}

impl Display for Transaction {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "{:}", self.account_id) //TODO: implement
    }
}

impl Debug for Transaction {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "{:}", self.account_id) //TODO: implement
    }
}
