//! This module contains query related Iroha functionality.

use crate::prelude::*;
use iroha_data_model::prelude::*;
use iroha_derive::Io;
use iroha_error::{derive::Error, Error, Result};
use iroha_http_server::http::{
    HttpRequest, HttpResponseError, StatusCode, HTTP_CODE_BAD_REQUEST,
    HTTP_CODE_INTERNAL_SERVER_ERROR,
};
use iroha_version::{scale::DecodeVersioned, Version};
use parity_scale_codec::{Decode, Encode};

use std::convert::TryFrom;
use std::error::Error as StdError;
use std::fmt;

/// Query Request verified on the Iroha node side.
#[derive(Debug, Io, Encode, Decode)]
pub struct VerifiedQueryRequest {
    /// Timestamp of the query creation.
    #[codec(compact)]
    pub timestamp_ms: u128,
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
    fn execute(&self, world_state_view: &WorldStateView) -> Result<Value>;
}

impl TryFrom<SignedQueryRequest> for VerifiedQueryRequest {
    type Error = Error;

    fn try_from(sr: SignedQueryRequest) -> Result<Self> {
        sr.signature.verify(sr.hash().as_ref()).map(|_| Self {
            timestamp_ms: sr.timestamp_ms,
            signature: sr.signature,
            query: sr.query,
        })
    }
}

/// Unsupported version error
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub struct UnsupportedVersionError {
    /// Version that we got
    pub version: u8,
}

impl UnsupportedVersionError {
    /// Expected version
    pub const fn expected_version() -> u8 {
        1
    }
}

impl StdError for UnsupportedVersionError {}

impl fmt::Display for UnsupportedVersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Unsupported version. Expected version {}, got: {}",
            Self::expected_version(),
            self.version
        )
    }
}

/// Decode verified query error
#[derive(Error, Debug)]
pub enum AcceptQueryError {
    /// Transaction has unsupported version
    #[error("Transaction has unsupported version")]
    UnsupportedQueryVersion(#[source] UnsupportedVersionError),
    /// Failed to decode signed query
    #[error("Failed to decode signed query")]
    DecodeVersionedSignedQuery(#[source] iroha_version::error::Error),
    /// Failed to verify query request
    #[error("Failed to verify query request")]
    VerifyQuery(iroha_error::Error),
}

impl HttpResponseError for AcceptQueryError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::UnsupportedQueryVersion(_) | Self::VerifyQuery(_) => {
                HTTP_CODE_INTERNAL_SERVER_ERROR
            }
            Self::DecodeVersionedSignedQuery(_) => HTTP_CODE_BAD_REQUEST,
        }
    }

    fn error_body(&self) -> Vec<u8> {
        self.to_string().into()
    }
}

impl TryFrom<&HttpRequest> for VerifiedQueryRequest {
    type Error = AcceptQueryError;

    fn try_from(request: &HttpRequest) -> Result<Self, Self::Error> {
        let query = VersionedSignedQueryRequest::decode_versioned(&request.body)
            .map_err(AcceptQueryError::DecodeVersionedSignedQuery)?;
        let version = query.version();
        let query: SignedQueryRequest = query
            .into_v1()
            .ok_or(AcceptQueryError::UnsupportedQueryVersion(
                UnsupportedVersionError { version },
            ))?
            .into();
        VerifiedQueryRequest::try_from(query).map_err(AcceptQueryError::VerifyQuery)
    }
}
impl TryFrom<HttpRequest> for VerifiedQueryRequest {
    type Error = AcceptQueryError;

    fn try_from(request: HttpRequest) -> Result<Self, Self::Error> {
        Self::try_from(&request)
    }
}

impl Query for QueryBox {
    fn execute(&self, world_state_view: &WorldStateView) -> Result<Value> {
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
            QueryBox::FindAllParameters(query) => query.execute(world_state_view),
        }
    }
}
