use crate::{asset, prelude::*};
use parity_scale_codec::{Decode, Encode};

#[derive(Encode, Decode)]
pub struct Request {
    pub timestamp: u128,
    pub signature: Option<Signature>,
    pub query: IrohaQuery,
}

#[derive(Encode, Decode)]
pub enum IrohaQuery {
    GetAccountAssets(asset::query::GetAccountAssets),
}

#[derive(Debug, Encode, Decode)]
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

/// ```
/// use iroha::{query::Request, asset::query::GetAccountAssets, prelude::*};
///
/// let query_payload = &GetAccountAssets::new(Id::new("account","domain"));
/// let result: Vec<u8> = query_payload.into();
/// ```
impl std::convert::From<&Request> for Vec<u8> {
    fn from(payload: &Request) -> Self {
        payload.encode()
    }
}

/// # Example
/// ```
/// # use iroha::{query::Request, asset::query::GetAccountAssets, prelude::*};
///
/// # let query_payload = &GetAccountAssets::build_request(Id::new("account","domain"));
/// # let result: Vec<u8> = query_payload.into();
/// let query_payload: Request = result.into();
/// ```
impl std::convert::From<Vec<u8>> for Request {
    fn from(payload: Vec<u8>) -> Self {
        Request::decode(&mut payload.as_slice()).expect("Failed to deserialize payload.")
    }
}

impl std::convert::From<Vec<u8>> for QueryResult {
    fn from(payload: Vec<u8>) -> Self {
        QueryResult::decode(&mut payload.as_slice()).expect("Failed to deserialize payload.")
    }
}

impl std::convert::From<&QueryResult> for Vec<u8> {
    fn from(payload: &QueryResult) -> Self {
        payload.encode()
    }
}
