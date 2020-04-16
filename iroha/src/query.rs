use crate::{asset, prelude::*};
use iroha_derive::Io;
use parity_scale_codec::{Decode, Encode};

#[derive(Debug, Io, Encode, Decode)]
pub struct QueryRequest {
    pub timestamp: u128,
    pub signature: Option<Signature>,
    pub query: IrohaQuery,
}

#[derive(Debug, Encode, Decode)]
pub enum IrohaQuery {
    GetAccountAssets(asset::query::GetAccountAssets),
}

#[derive(Debug, Io, Encode, Decode)]
pub enum QueryResult {
    GetAccountAssets(asset::query::GetAccountAssetsResult),
}

impl IrohaQuery {
    pub fn execute(&self, world_state_view: &WorldStateView) -> Result<QueryResult, String> {
        match self {
            IrohaQuery::GetAccountAssets(query) => query.execute(world_state_view),
        }
    }
}

pub trait Query {
    fn execute(&self, world_state_view: &WorldStateView) -> Result<QueryResult, String>;
}
