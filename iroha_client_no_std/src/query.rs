//! This module contains query related Iroha functionality.

use crate::{account, asset};
use iroha_crypto::{Hash, KeyPair, Signature};
use iroha_derive::Io;
use parity_scale_codec::{Decode, Encode};
use std::time::SystemTime;

/// I/O ready structure to send queries.
#[derive(Debug, Io, Encode, Decode, Clone)]
pub struct QueryRequest {
    /// Timestamp of the query creation.
    pub timestamp: String,
    /// Query definition.
    pub query: IrohaQuery,
}

impl QueryRequest {
    /// Constructs a new request with the `query`.
    pub fn new(query: IrohaQuery) -> Self {
        QueryRequest {
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("Failed to get System Time.")
                .as_millis()
                .to_string(),
            query,
        }
    }

    /// `Hash` of this request.
    pub fn hash(&self) -> Hash {
        let mut payload: Vec<u8> = self.query.clone().into();
        payload.extend_from_slice(self.timestamp.as_bytes());
        iroha_crypto::hash(payload)
    }

    /// Consumes self and returns a signed `QueryReuest`.
    pub fn sign(self, key_pair: &KeyPair) -> Result<SignedQueryRequest, String> {
        Ok(SignedQueryRequest {
            timestamp: self.timestamp.clone(),
            signature: Signature::new(key_pair.clone(), &self.hash())?,
            query: self.query,
        })
    }
}

/// I/O ready structure to send queries.
#[derive(Debug, Io, Encode, Decode)]
pub struct SignedQueryRequest {
    /// Timestamp of the query creation.
    pub timestamp: String,
    /// Signature of the client who sends this query.
    pub signature: Signature,
    /// Query definition.
    pub query: IrohaQuery,
}

impl SignedQueryRequest {
    /// `Hash` of this request.
    pub fn hash(&self) -> Hash {
        let mut payload: Vec<u8> = self.query.clone().into();
        payload.extend_from_slice(self.timestamp.as_bytes());
        iroha_crypto::hash(payload)
    }

    /// Verifies the signature of this query.
    pub fn verify(&self) -> Result<(), String> {
        self.signature.verify(&self.hash())
    }
}

/// Enumeration of all legal Iroha Queries.
#[derive(Clone, Debug, Encode, Decode, Io)]
pub enum IrohaQuery {
    /// Query all Assets related to the Account.
    GetAccountAssets(asset::query::GetAccountAssets),
    /// Query Account information.
    GetAccount(account::query::GetAccount),
}

/// Result of queries execution.
#[derive(Debug, Io, Encode, Decode)]
pub enum QueryResult {
    /// Query all Assets related to the Account result.
    GetAccountAssets(asset::query::GetAccountAssetsResult),
    /// Query Account information.
    GetAccount(account::query::GetAccountResult),
}
