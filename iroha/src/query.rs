//! This module contains query related Iroha functionality.

use crate::{account, asset, domain, prelude::*};
use iroha_crypto::Hash;
use iroha_derive::Io;
use parity_scale_codec::{Decode, Encode};
use std::time::SystemTime;

/// I/O ready structure to send queries.
#[derive(Debug, Io, Encode, Decode, Clone)]
pub struct QueryRequest {
    //TODO: why use `String` for timestamp? maybe replace it with milliseconds in `u64`
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
    pub query: IrohaQuery,
}

/// Enumeration of all possible Iroha Queries.
#[derive(Clone, Debug, Encode, Decode, Io)]
pub enum IrohaQuery {
    /// Query all Assets.
    GetAllAssets(asset::query::GetAllAssets),
    /// Query all Assets Definitions.
    GetAllAssetsDefinitions(asset::query::GetAllAssetsDefinitions),
    /// Query all Assets related to the Account.
    GetAccountAssets(asset::query::GetAccountAssets),
    /// Query all Assets with defined Definition related to the Account.
    GetAccountAssetsWithDefinition(asset::query::GetAccountAssetsWithDefinition),
    /// Query all Accounts.
    GetAllAccounts(account::query::GetAllAccounts),
    /// Query Account information.
    GetAccount(account::query::GetAccount),
    /// Query Domains information.
    GetAllDomains(domain::query::GetAllDomains),
    /// Query Domain information.
    GetDomain(domain::query::GetDomain),
}

/// Result of queries execution.
#[derive(Clone, Debug, Io, Encode, Decode)]
pub enum QueryResult {
    /// Query all Assets.
    GetAllAssets(asset::query::GetAllAssetsResult),
    /// Query all Assets Definitions.
    GetAllAssetsDefinitions(asset::query::GetAllAssetsDefinitionsResult),
    /// Query all Assets related to the Account result.
    GetAccountAssets(asset::query::GetAccountAssetsResult),
    /// Query all Assets with defined Definition related to the Account.
    GetAccountAssetsWithDefinition(asset::query::GetAccountAssetsWithDefinitionResult),
    /// Query all Accounts.
    GetAllAccounts(account::query::GetAllAccountsResult),
    /// Query Account information.
    GetAccount(account::query::GetAccountResult),
    /// Query Domains information.
    GetAllDomains(domain::query::GetAllDomainsResult),
    /// Query Domain information.
    GetDomain(domain::query::GetDomainResult),
}

impl IrohaQuery {
    /// Execute query on the `WorldStateView`.
    ///
    /// Returns Ok(QueryResult) if succeeded and Err(String) if failed.
    pub fn execute(&self, world_state_view: &WorldStateView) -> Result<QueryResult, String> {
        match self {
            IrohaQuery::GetAllAssets(query) => query.execute(world_state_view),
            IrohaQuery::GetAllAssetsDefinitions(query) => query.execute(world_state_view),
            IrohaQuery::GetAccountAssets(query) => query.execute(world_state_view),
            IrohaQuery::GetAccountAssetsWithDefinition(query) => query.execute(world_state_view),
            IrohaQuery::GetAllAccounts(query) => query.execute(world_state_view),
            IrohaQuery::GetAccount(query) => query.execute(world_state_view),
            IrohaQuery::GetAllDomains(query) => query.execute(world_state_view),
            IrohaQuery::GetDomain(query) => query.execute(world_state_view),
        }
    }
}

/// This trait should be implemented for all Iroha Queries.
pub trait Query {
    /// Execute query on the `WorldStateView`.
    ///
    /// Returns Ok(QueryResult) if succeeded and Err(String) if failed.
    fn execute(&self, world_state_view: &WorldStateView) -> Result<QueryResult, String>;
}
