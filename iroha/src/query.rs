//! This module contains query related Iroha functionality.

use crate::{account::query::*, asset::query::*, domain::query::*, prelude::*};
use iroha_crypto::Hash;
use iroha_data_model::prelude::*;
use iroha_derive::Io;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// I/O ready structure to send queries.
#[derive(Debug, Io, Encode, Decode, Clone)]
pub struct QueryRequest {
    //TODO: why use `String` for timestamp? maybe replace it with milliseconds in `u64`
    /// Timestamp of the query creation.
    pub timestamp: String,
    /// Query definition.
    pub query: QueryBox,
}

impl QueryRequest {
    /// Constructs a new request with the `query`.
    pub fn new(query: QueryBox) -> Self {
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
    pub query: QueryBox,
}

impl SignedQueryRequest {
    /// `Hash` of this request.
    pub fn hash(&self) -> Hash {
        let mut payload: Vec<u8> = self.query.clone().into();
        payload.extend_from_slice(self.timestamp.as_bytes());
        iroha_crypto::hash(payload)
    }

    /// Verifies the signature of this query.
    pub fn verify(self) -> Result<VerifiedQueryRequest, String> {
        self.signature
            .verify(&self.hash())
            .map(|_| VerifiedQueryRequest {
                timestamp: self.timestamp,
                signature: self.signature,
                query: self.query,
            })
    }
}

/// Query Request verified on the Iroha node side.
#[derive(Debug, Io, Encode, Decode)]
pub struct VerifiedQueryRequest {
    /// Timestamp of the query creation.
    pub timestamp: String,
    /// Signature of the client who sends this query.
    pub signature: Signature,
    /// Query definition.
    pub query: QueryBox,
}

/// This trait should be implemented for all Iroha Queries.
pub trait Query {
    /// Execute query on the `WorldStateView`.
    ///
    /// Returns Ok(QueryResult) if succeeded and Err(String) if failed.
    fn execute(&self, world_state_view: &WorldStateView) -> Result<QueryResult, String>;
}

impl Query for QueryBox {
    fn execute(&self, world_state_view: &WorldStateView) -> Result<QueryResult, String> {
        Err("Not implmented yet.".to_string())
    }
}

/// Sized container for all possible Query results.
#[derive(Debug, Clone, Io, Serialize, Deserialize, Encode, Decode)]
pub enum QueryResult {
    /// `FindAllAccounts` variant.
    FindAllAccounts(Box<FindAllAccountsResult>),
    /// `FindAccountById` variant.
    FindAccountById(Box<FindAccountByIdResult>),
    /// `FindAccountsByName` variant.
    FindAccountsByName,
    /// `FindAccountsByDomainName` variant.
    FindAccountsByDomainName,
    /// `FindAllAssets` variant.
    FindAllAssets(Box<FindAllAssetsResult>),
    /// `FindAllAssetsDefinitions` variant.
    FindAllAssetsDefinitions(Box<FindAllAssetsDefinitionsResult>),
    /// `FindAssetById` variant.
    FindAssetById,
    /// `FindAssetByName` variant.
    FindAssetByName,
    /// `FindAssetsByAccountId` variant.
    FindAssetsByAccountId(Box<FindAssetsByAccountIdResult>),
    /// `FindAssetsByAssetDefinitionId` variant.
    FindAssetsByAssetDefinitionId,
    /// `FindAssetsByDomainName` variant.
    FindAssetsByDomainName,
    /// `FindAssetsByAccountIdAndAssetDefinitionId` variant.
    FindAssetsByAccountIdAndAssetDefinitionId(Box<FindAssetsByAccountIdAndAssetDefinitionIdResult>),
    /// `FindAssetsByDomainNameAndAssetDefinitionId` variant.
    FindAssetsByDomainNameAndAssetDefinitionId,
    /// `FindAssetQuantityById` variant.
    FindAssetQuantityById,
    /// `FindAllDomains` variant.
    FindAllDomains(Box<FindAllDomainsResult>),
    /// `FindDomainByName` variant.
    FindDomainByName(Box<FindDomainByNameResult>),
    /// `FindAllPeers` variant.
    FindAllPeers,
    /// `FindPeerById` variant.
    FindPeerById,
}
