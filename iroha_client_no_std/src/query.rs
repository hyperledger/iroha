//! This module contains query related Iroha functionality.

use crate::{account, asset};
use iroha::crypto::Signature;
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

/// Enumeration of all legal Iroha Queries.
#[derive(Clone, Debug, Encode, Decode)]
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
