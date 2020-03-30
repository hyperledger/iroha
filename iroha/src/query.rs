use crate::prelude::*;
use std::time::SystemTime;

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Query {
    query_type: u32,
    timestamp: u128,
    signature: Option<Signature>,
    payload: Vec<u8>,
}

/// ```
/// use iroha::{query::{Query, GetAccountAssets}, prelude::*};
///
/// let query_payload = &GetAccountAssets::new(Id::new("account","domain"));
/// let result: Vec<u8> = query_payload.into();
/// ```
impl std::convert::From<&Query> for Vec<u8> {
    fn from(payload: &Query) -> Self {
        bincode::serialize(payload).expect("Failed to serialize payload.")
    }
}

/// # Example
/// ```
/// # use iroha::{query::{Query, GetAccountAssets}, prelude::*};
///
/// # let query_payload = &GetAccountAssets::build_query(Id::new("account","domain"));
/// # let result: Vec<u8> = query_payload.into();
/// let query_payload: Query = result.into();
/// ```
impl std::convert::From<Vec<u8>> for Query {
    fn from(payload: Vec<u8>) -> Self {
        bincode::deserialize(&payload).expect("Failed to deserialize payload.")
    }
}

/// To get the state of all assets in an account (a balance),
/// GetAccountAssets query can be used.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct GetAccountAssets {
    account_id: Id,
}

impl GetAccountAssets {
    pub fn new(account_id: Id) -> GetAccountAssets {
        GetAccountAssets { account_id }
    }

    pub fn build_query(account_id: Id) -> Query {
        let payload = &GetAccountAssets { account_id };
        Query {
            query_type: 10,
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("Failed to get System Time.")
                .as_millis(),
            signature: Option::None,
            payload: payload.into(),
        }
    }
}

/// ```
/// use iroha::{query::{Query, GetAccountAssets}, prelude::*};
///
/// let query_payload = &GetAccountAssets::new(Id::new("account","domain"));
/// let result: Vec<u8> = query_payload.into();
/// ```
impl std::convert::From<&GetAccountAssets> for Vec<u8> {
    fn from(payload: &GetAccountAssets) -> Self {
        bincode::serialize(payload).expect("Failed to serialize payload.")
    }
}

/// # Example
/// ```
/// # use iroha::{query::{Query, GetAccountAssets}, prelude::*};
///
/// # let query_payload = &GetAccountAssets::new(Id::new("account","domain"));
/// # let result: Vec<u8> = query_payload.into();
/// let query_payload: GetAccountAssets = result.into();
/// ```
impl std::convert::From<Vec<u8>> for GetAccountAssets {
    fn from(payload: Vec<u8>) -> Self {
        bincode::deserialize(&payload).expect("Failed to deserialize payload.")
    }
}
