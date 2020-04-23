use crate::prelude::*;
use iroha_derive::Io;
use parity_scale_codec::{Decode, Encode};
use std::time::SystemTime;
use ursa::{
    keys::PrivateKey,
    signatures::{ed25519::Ed25519Sha512, Signer},
};

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
    Requested {
        request: TransactionRequest,
        signatures: Vec<Signature>,
    },
    Accepted {
        request: TransactionRequest,
        signatures: Vec<Signature>,
    },
    Signed {
        request: TransactionRequest,
        signatures: Vec<Signature>,
    },
    Valid {
        request: TransactionRequest,
        signatures: Vec<Signature>,
    },
}

impl Transaction {
    pub fn new(
        instructions: Vec<Contract>,
        account_id: Id,
        public_key: &PublicKey,
        private_key: &PrivateKey,
    ) -> Transaction {
        let request = TransactionRequest {
            instructions,
            account_id,
            creation_time: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("Failed to get System Time.")
                .as_millis()
                .to_string(),
        };
        let bytes: Vec<u8> = Vec::from(&request);
        let transaction_signature = Signer::new(&Ed25519Sha512, &private_key)
            .sign(&bytes)
            .expect("Failed to sign transaction.");
        let mut signature = [0; 64];
        signature.copy_from_slice(&transaction_signature);
        let signature = Signature::new(*public_key, signature);
        Transaction::Requested {
            request,
            signatures: vec![signature],
        }
    }

    pub fn accept(self) -> Result<Transaction, String> {
        if let Transaction::Requested {
            request,
            signatures,
        } = self
        {
            for signature in &signatures {
                if signature.verify(&Vec::from(&request)).is_err() {
                    return Err("Failed to verify signatures.".to_string());
                }
            }
            Ok(Transaction::Accepted {
                request,
                signatures,
            })
        } else {
            Err("Transaction should be in Requested state to be accepted.".to_string())
        }
    }

    pub fn sign(self, new_signatures: Vec<Signature>) -> Result<Transaction, String> {
        if let Transaction::Accepted {
            request,
            signatures,
        } = self
        {
            Ok(Transaction::Signed {
                request,
                signatures: vec![signatures, new_signatures]
                    .into_iter()
                    .flatten()
                    .collect(),
            })
        } else {
            Err("Transaction should be in Accepted state to be signed.".to_string())
        }
    }

    pub fn validate(self, world_state_view: &WorldStateView) -> Result<Transaction, String> {
        if let Transaction::Signed {
            request,
            signatures,
        } = self
        {
            let mut world_state_view = world_state_view.clone();
            for instruction in &request.instructions {
                instruction.invoke(&mut world_state_view)?;
            }
            Ok(Transaction::Valid {
                request,
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

impl From<&Transaction> for TransactionRequest {
    fn from(transaction: &Transaction) -> TransactionRequest {
        match transaction {
            Transaction::Requested { request, .. }
            | Transaction::Accepted { request, .. }
            | Transaction::Signed { request, .. }
            | Transaction::Valid { request, .. } => request.clone(),
        }
    }
}
