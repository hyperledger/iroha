//! This module contains query related Iroha functionality.

use std::convert::TryFrom;
use std::error::Error as StdError;
use std::fmt;

use iroha_data_model::prelude::*;
use iroha_derive::Io;
use iroha_error::{derive::Error, Error, Result};
use iroha_http_server::http::{
    HttpResponseError, RawHttpRequest, StatusCode, HTTP_CODE_BAD_REQUEST,
    HTTP_CODE_INTERNAL_SERVER_ERROR,
};
use iroha_version::{scale::DecodeVersioned, Version};
use parity_scale_codec::{Decode, Encode};

use crate::prelude::*;

/// Query Request verified on the Iroha node side.
#[derive(Debug, Io, Encode, Decode)]
#[non_exhaustive]
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
#[allow(clippy::missing_errors_doc)]
pub trait Query: QueryOutput {
    /// Execute query on the `WorldStateView`.
    /// Should not mutate `WorldStateView`!
    ///
    /// Returns Ok(QueryResult) if succeeded and Err(String) if failed.
    fn execute(&self, world_state_view: &WorldStateView) -> Result<Self::Output>;

    /// Executes query and maps it into value
    fn execute_into_value(&self, world_state_view: &WorldStateView) -> Result<Value> {
        self.execute(world_state_view).map(Into::into)
    }
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
#[allow(clippy::exhaustive_structs)]
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
        match *self {
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

impl TryFrom<&RawHttpRequest> for VerifiedQueryRequest {
    type Error = AcceptQueryError;

    fn try_from(request: &RawHttpRequest) -> Result<Self, Self::Error> {
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
impl TryFrom<RawHttpRequest> for VerifiedQueryRequest {
    type Error = AcceptQueryError;

    fn try_from(request: RawHttpRequest) -> Result<Self, Self::Error> {
        Self::try_from(&request)
    }
}

impl Query for QueryBox {
    fn execute(&self, wsv: &WorldStateView) -> Result<Value> {
        use QueryBox::*;

        match self {
            FindAllAccounts(query) => query.execute_into_value(wsv),
            FindAccountById(query) => query.execute_into_value(wsv),
            FindAccountsByName(query) => query.execute_into_value(wsv),
            FindAccountsByDomainName(query) => query.execute_into_value(wsv),
            FindAllAssets(query) => query.execute_into_value(wsv),
            FindAllAssetsDefinitions(query) => query.execute_into_value(wsv),
            FindAssetById(query) => query.execute_into_value(wsv),
            FindAssetsByName(query) => query.execute_into_value(wsv),
            FindAssetsByAccountId(query) => query.execute_into_value(wsv),
            FindAssetsByAssetDefinitionId(query) => query.execute_into_value(wsv),
            FindAssetsByDomainName(query) => query.execute_into_value(wsv),
            FindAssetsByAccountIdAndAssetDefinitionId(query) => query.execute_into_value(wsv),
            FindAssetsByDomainNameAndAssetDefinitionId(query) => query.execute_into_value(wsv),
            FindAssetQuantityById(query) => query.execute_into_value(wsv),
            FindAllDomains(query) => query.execute_into_value(wsv),
            FindDomainByName(query) => query.execute_into_value(wsv),
            FindAllPeers(query) => query.execute_into_value(wsv),
            FindAssetKeyValueByIdAndKey(query) => query.execute_into_value(wsv),
            FindAccountKeyValueByIdAndKey(query) => query.execute_into_value(wsv),
            FindTransactionsByAccountId(query) => query.execute_into_value(wsv),
            FindPermissionTokensByAccountId(query) => query.execute_into_value(wsv),

            #[cfg(feature = "roles")]
            FindAllRoles(query) => query.execute_into_value(wsv),
            #[cfg(feature = "roles")]
            FindRolesByAccountId(query) => query.execute_into_value(wsv),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    use iroha_crypto::KeyPair;
    use iroha_data_model::{domain::DomainsMap, peer::PeersIds};

    use super::*;

    fn world_with_test_domains() -> Result<World> {
        let domains = DomainsMap::new();
        let mut domain = Domain::new("wonderland");
        let account_id = AccountId::new("alice", "wonderland");
        let mut account = Account::new(account_id.clone());
        let key_pair = KeyPair::generate()?;
        account.signatories.push(key_pair.public_key);
        drop(domain.accounts.insert(account_id.clone(), account));
        let asset_definition_id = AssetDefinitionId::new("rose", "wonderland");
        drop(domain.asset_definitions.insert(
            asset_definition_id.clone(),
            AssetDefinitionEntry::new(
                AssetDefinition::new(asset_definition_id, AssetValueType::Quantity),
                account_id,
            ),
        ));
        drop(domains.insert("wonderland".to_string(), domain));
        Ok(World::with(domains, PeersIds::new()))
    }

    #[test]
    fn asset_store() -> Result<()> {
        let wsv = WorldStateView::new(world_with_test_domains()?);
        let account_id = AccountId::new("alice", "wonderland");
        let asset_definition_id = AssetDefinitionId::new("rose", "wonderland");
        let asset_id = AssetId::new(asset_definition_id, account_id);
        let mut store = Metadata::new();
        drop(store.insert_with_limits(
            "Bytes".to_owned(),
            Value::Vec(vec![Value::U32(1), Value::U32(2), Value::U32(3)]),
            MetadataLimits::new(10, 100),
        ));
        wsv.add_asset(Asset::new(asset_id.clone(), AssetValue::Store(store)))?;
        let bytes = FindAssetKeyValueByIdAndKey::new(asset_id, "Bytes".to_owned()).execute(&wsv)?;
        assert_eq!(
            bytes,
            Value::Vec(vec![Value::U32(1), Value::U32(2), Value::U32(3)])
        );
        Ok(())
    }

    #[test]
    fn account_metadata() -> Result<()> {
        let wsv = WorldStateView::new(world_with_test_domains()?);
        let account_id = AccountId::new("alice", "wonderland");
        wsv.modify_account(&account_id, |account| {
            drop(account.metadata.insert_with_limits(
                "Bytes".to_string(),
                Value::Vec(vec![Value::U32(1), Value::U32(2), Value::U32(3)]),
                MetadataLimits::new(10, 100),
            )?);
            Ok(())
        })?;
        let bytes =
            FindAccountKeyValueByIdAndKey::new(account_id, "Bytes".to_owned()).execute(&wsv)?;
        assert_eq!(
            bytes,
            Value::Vec(vec![Value::U32(1), Value::U32(2), Value::U32(3)])
        );
        Ok(())
    }
}
