//! This module contains query related Iroha functionality.

use crate::prelude::*;
use iroha_data_model::prelude::*;
use iroha_derive::Io;
use parity_scale_codec::{Decode, Encode};

//TODO: replace with From<SignedQueryRequest> for VerifiedQueryRequest.
/// Verify query trait.
pub trait Verify {
    /// Verify query.
    fn verify(self) -> Result<VerifiedQueryRequest, String>;
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

//TODO: replace with From<SignedQueryRequest> for VerifiedQueryRequest.
impl Verify for SignedQueryRequest {
    /// Verifies the signature of this query.
    fn verify(self) -> Result<VerifiedQueryRequest, String> {
        self.signature
            .verify(self.hash().as_ref())
            .map(|_| VerifiedQueryRequest {
                timestamp: self.timestamp,
                signature: self.signature,
                query: self.query,
            })
    }
}

impl Query for QueryBox {
    fn execute(&self, world_state_view: &WorldStateView) -> Result<QueryResult, String> {
        match self {
            QueryBox::FindAllAccounts(query) => query.execute(world_state_view),
            QueryBox::FindAccountById(query) => query.execute(world_state_view),
            QueryBox::FindAccountsByName(query) => query.execute(world_state_view),
            QueryBox::FindAccountsByDomainName(query) => query.execute(world_state_view),
            QueryBox::FindAllAssets(query) => query.execute(world_state_view),
            QueryBox::FindAllAssetsDefinitions(query) => query.execute(world_state_view),
            QueryBox::FindAssetById(query) => query.execute(world_state_view),
            QueryBox::FindAssetsByName(query) => query.execute(world_state_view),
            QueryBox::FindAssetsByAccountId(query) => query.execute(world_state_view),
            QueryBox::FindAssetsByAssetDefinitionId(query) => query.execute(world_state_view),
            QueryBox::FindAssetsByDomainName(query) => query.execute(world_state_view),
            QueryBox::FindAssetsByAccountIdAndAssetDefinitionId(query) => {
                query.execute(world_state_view)
            }
            QueryBox::FindAssetsByDomainNameAndAssetDefinitionId(query) => {
                query.execute(world_state_view)
            }
            QueryBox::FindAssetQuantityById(query) => query.execute(world_state_view),
            QueryBox::FindAllDomains(query) => query.execute(world_state_view),
            QueryBox::FindDomainByName(query) => query.execute(world_state_view),
            QueryBox::FindAllPeers(query) => query.execute(world_state_view),
            QueryBox::FindPeerById(query) => query.execute(world_state_view),
            QueryBox::FindAllParameters(query) => query.execute(world_state_view),
        }
    }
}
