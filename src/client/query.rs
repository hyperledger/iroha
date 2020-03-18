use crate::model::crypto::Signature;
use std::time::SystemTime;

/// Represents client's query to `Iroha` peer.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Query {
    timestamp: u128,
    signature: Option<Signature>,
}

impl Query {
    pub fn builder() -> QueryBuilder {
        QueryBuilder {
            signature: Option::None,
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("Failed to get System Time.")
                .as_millis(),
        }
    }
}

pub struct QueryBuilder {
    timestamp: u128,
    signature: Option<Signature>,
}

impl QueryBuilder {
    pub fn signed(mut self, signature: Signature) -> Self {
        self.signature = Option::Some(signature);
        self
    }

    pub fn build(self) -> Query {
        Query {
            timestamp: self.timestamp,
            signature: self.signature,
        }
    }
}

/// # Example
/// ```
/// use iroha::{model::crypto::Signature,client::query::Query};
///
/// let query_payload = &Query::builder().build();
/// let result: Vec<u8> = query_payload.into();
/// ```
impl std::convert::From<&Query> for Vec<u8> {
    fn from(payload: &Query) -> Self {
        bincode::serialize(payload).expect("Failed to serialize payload.")
    }
}

/// # Example
/// ```
/// # use iroha::{model::crypto::Signature,client::query::Query};
///
/// # let query_payload = &Query::builder().build();
/// # let result: Vec<u8> = query_payload.into();
/// let query_payload: Query = result.into();
/// ```
impl std::convert::From<Vec<u8>> for Query {
    fn from(payload: Vec<u8>) -> Self {
        bincode::deserialize(&payload).expect("Failed to deserialize payload.")
    }
}

//TODO: should be generated DSL
pub struct AssetsQueries {}

impl AssetsQueries {
    pub fn by_id(&self, _asset_id: &str) -> Result<Asset, ()> {
        Ok(Asset {
            account_id: "account2_name@domain".to_string(),
        })
    }
}

pub struct Asset {
    pub account_id: String,
}
