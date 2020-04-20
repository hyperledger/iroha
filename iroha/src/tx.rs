use crate::prelude::*;
use iroha_derive::Io;
use parity_scale_codec::{Decode, Encode};
use std::time::SystemTime;

/// This structure represents transaction in non-trusted form.
///
/// `Iroha` and its' clients use this structure to send via network.
/// Direct usage in business logic is strongly prohibited.
/// Wrap this structure in `Transaction::Requested` and
/// go through `Transaction` lifecycle.
#[derive(Clone, Debug, Io, Encode, Decode)]
pub struct TransactionRequest {
    /// Account ID of transaction creator (username@domain).
    account_id: Id,
    /// An ordered set of instructions.
    pub instructions: Vec<Contract>,
    signatures: Vec<Signature>,
    /// Time of creation (unix time, in milliseconds).
    creation_time: String,
}

/// An ordered set of instructions, which is applied to the ledger atomically.
///
/// Transactions received by `Iroha` from external resources (clients, peers, etc.)
/// go through several steps before will be added to the blockchain and stored.
/// Starting in form of `Requested` transaction it changes state based on interactions
/// with `Iroha` subsystems.
#[derive(Clone, Debug, Io, Encode, Decode)]
pub enum Transaction {
    Requested(TransactionRequest),
    Accepted(TransactionRequest),
    Signed(TransactionRequest),
    Valid(TransactionRequest),
}

impl Transaction {
    pub fn new(instructions: Vec<Contract>, account_id: Id) -> Transaction {
        Transaction::Requested(TransactionRequest {
            instructions,
            account_id,
            creation_time: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("Failed to get System Time.")
                .as_millis()
                .to_string(),
            signatures: Vec::new(),
        })
    }

    pub fn accept(self) -> Result<Transaction, String> {
        if let Transaction::Requested(transaction_request) = self {
            Ok(Transaction::Accepted(transaction_request))
        } else {
            Err("Transaction should be in Requested state to be accepted.".to_string())
        }
    }

    pub fn sign(self, new_signatures: Vec<Signature>) -> Result<Transaction, String> {
        if let Transaction::Accepted(transaction_request) = self {
            Ok(Transaction::Signed(TransactionRequest {
                signatures: vec![transaction_request.signatures, new_signatures]
                    .into_iter()
                    .flatten()
                    .collect(),
                ..transaction_request
            }))
        } else {
            Err("Transaction should be in Accepted state to be signed.".to_string())
        }
    }

    pub fn validate(self) -> Result<Transaction, String> {
        if let Transaction::Signed(transaction_request) = self {
            Ok(Transaction::Valid(transaction_request))
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

impl From<&Transaction> for TransactionRequest {
    fn from(transaction: &Transaction) -> TransactionRequest {
        match transaction {
            Transaction::Requested(transaction_request)
            | Transaction::Accepted(transaction_request)
            | Transaction::Signed(transaction_request)
            | Transaction::Valid(transaction_request) => transaction_request.clone(),
        }
    }
}
