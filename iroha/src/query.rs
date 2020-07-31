//! This module contains query related Iroha functionality.

use crate::{account, asset, domain, prelude::*};
use iroha_derive::Io;
use parity_scale_codec::{Decode, Encode};

/// I/O ready structure to send queries.
#[derive(Debug, Io, Encode, Decode)]
pub struct QueryRequest {
    /// Timestamp of the query creation.
    pub timestamp: String,
    /// Optional query signature.
    pub signature: Option<Signature>,
    /// Query definition.
    pub query: IrohaQuery,
}

/// Enumeration of all possible Iroha Queries.
#[derive(Clone, Debug, Encode, Decode)]
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
