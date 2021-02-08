//! This module contains query related Iroha functionality.

use crate::prelude::*;
use iroha_data_model::prelude::*;
use iroha_derive::Io;
use parity_scale_codec::{Decode, Encode};

use std::convert::TryFrom;

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
    fn execute(&self, world_state_view: &WorldStateView) -> Result<Value, String>;
}

impl TryFrom<SignedQueryRequest> for VerifiedQueryRequest {
    type Error = String;

    fn try_from(sr: SignedQueryRequest) -> Result<Self, Self::Error> {
        sr.signature.verify(sr.hash().as_ref()).map(|_| Self {
            timestamp: sr.timestamp,
            signature: sr.signature,
            query: sr.query,
        })
    }
}

impl Query for QueryBox {
    fn execute(&self, world_state_view: &WorldStateView) -> Result<Value, String> {
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
