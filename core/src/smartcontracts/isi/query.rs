//! This module contains query related Iroha functionality.

use std::{convert::TryFrom, error::Error as StdError, fmt};

use eyre::{eyre, Result};
use iroha_crypto::{SignatureOf, SignatureVerificationFail};
use iroha_data_model::{prelude::*, query};
use iroha_derive::Io;
use iroha_version::{scale::DecodeVersioned, Version};
use parity_scale_codec::{Decode, Encode};
use thiserror::Error;
use warp::{
    http::StatusCode,
    hyper::body::Bytes,
    reply::{self, Response},
    Reply,
};

use super::permissions::IsQueryAllowedBoxed;
use crate::{prelude::*, WorldTrait};

/// Query Request verified on the Iroha node side.
#[derive(Debug, Io, Encode, Decode)]
pub struct VerifiedQueryRequest {
    /// Payload.
    payload: query::Payload,
    /// Signature of the client who sends this query.
    signature: SignatureOf<query::Payload>,
}

impl VerifiedQueryRequest {
    /// Statefully validate query.
    /// Checks whether account exists and has the corresponding public key, also check permissions based on this account.
    ///
    /// # Errors
    /// Returns and error if one of the previously mentioned checks did not pass.
    pub fn validate<W: WorldTrait>(
        self,
        wsv: &WorldStateView<W>,
        query_validator: &IsQueryAllowedBoxed<W>,
    ) -> Result<ValidQueryRequest> {
        let account_has_public_key = wsv.map_account(&self.payload.account_id, |account| {
            account.signatories.contains(&self.signature.public_key)
        })?;
        if !account_has_public_key {
            return Err(eyre!(
                "Public key used for the signature does not correspond to the account."
            ));
        }
        query_validator
            .check(&self.payload.account_id, &self.payload.query, wsv)
            .map_err(|denial_reason| eyre!(denial_reason))?;
        Ok(ValidQueryRequest {
            query: self.payload.query,
        })
    }
}

impl TryFrom<SignedQueryRequest> for VerifiedQueryRequest {
    type Error = SignatureVerificationFail<query::Payload>;

    fn try_from(query: SignedQueryRequest) -> Result<Self, Self::Error> {
        query.signature.verify(&query.payload).map(|_| Self {
            payload: query.payload,
            signature: query.signature,
        })
    }
}

/// Query Request statefully validated on the Iroha node side.
#[derive(Debug, Io, Encode, Decode)]
pub struct ValidQueryRequest {
    query: QueryBox,
}

impl ValidQueryRequest {
    /// Execute contained query on the [`WorldStateView`].
    ///
    /// # Errors
    /// Returns an error if the query execution fails.
    pub fn execute<W: WorldTrait>(&self, wsv: &WorldStateView<W>) -> Result<Value> {
        self.query.execute(wsv)
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

/// Accept query error.
#[derive(Error, Debug)]
pub enum AcceptQueryError {
    /// Transaction has unsupported version
    #[error("Transaction has unsupported version")]
    UnsupportedQueryVersion(#[source] UnsupportedVersionError),
    /// Failed to decode signed query
    #[error("Failed to decode signed query")]
    DecodeVersionedSignedQuery(#[source] Box<iroha_version::error::Error>),
    /// Failed to verify query request
    #[error("Failed to verify query request")]
    VerifyQuery(#[source] SignatureVerificationFail<query::Payload>),
}

impl AcceptQueryError {
    /// Status code of our error
    pub const fn status_code(&self) -> StatusCode {
        use AcceptQueryError::*;
        match *self {
            UnsupportedQueryVersion(_) => StatusCode::INTERNAL_SERVER_ERROR,
            DecodeVersionedSignedQuery(_) | VerifyQuery(_) => StatusCode::BAD_REQUEST,
        }
    }
}

impl Reply for AcceptQueryError {
    fn into_response(self) -> Response {
        reply::with_status(self.to_string(), self.status_code()).into_response()
    }
}
impl warp::reject::Reject for AcceptQueryError {}

impl TryFrom<&Bytes> for VerifiedQueryRequest {
    type Error = AcceptQueryError;
    fn try_from(body: &Bytes) -> Result<Self, Self::Error> {
        let query = VersionedSignedQueryRequest::decode_versioned(body.as_ref())
            .map_err(|e| AcceptQueryError::DecodeVersionedSignedQuery(Box::new(e)))?;
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

impl<W: WorldTrait> Query<W> for QueryBox {
    fn execute(&self, wsv: &WorldStateView<W>) -> Result<Value> {
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
            FindAssetsByDomainNameAndAssetDefinitionId(query) => query.execute_into_value(wsv),
            FindAssetQuantityById(query) => query.execute_into_value(wsv),
            FindAllDomains(query) => query.execute_into_value(wsv),
            FindDomainByName(query) => query.execute_into_value(wsv),
            FindAllPeers(query) => query.execute_into_value(wsv),
            FindAssetKeyValueByIdAndKey(query) => query.execute_into_value(wsv),
            FindAccountKeyValueByIdAndKey(query) => query.execute_into_value(wsv),
            FindTransactionsByAccountId(query) => query.execute_into_value(wsv),
            FindTransactionByHash(query) => query.execute_into_value(wsv),
            FindPermissionTokensByAccountId(query) => query.execute_into_value(wsv),
            FindAssetDefinitionKeyValueByIdAndKey(query) => query.execute_into_value(wsv),

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
    use crate::wsv::World;

    fn world_with_test_domains() -> Result<World> {
        let domains = DomainsMap::new();
        let mut domain = Domain::new("wonderland");
        let account_id = AccountId::new("alice", "wonderland");
        let mut account = Account::new(account_id.clone());
        let key_pair = KeyPair::generate()?;
        account.signatories.push(key_pair.public_key);
        domain.accounts.insert(account_id.clone(), account);
        let asset_definition_id = AssetDefinitionId::new("rose", "wonderland");
        domain.asset_definitions.insert(
            asset_definition_id.clone(),
            AssetDefinitionEntry::new(
                AssetDefinition::new(asset_definition_id, AssetValueType::Quantity, true),
                account_id,
            ),
        );
        domains.insert("wonderland".to_string(), domain);
        Ok(World::with(domains, PeersIds::new()))
    }

    #[test]
    fn asset_store() -> Result<()> {
        let wsv = WorldStateView::new(world_with_test_domains()?);
        let account_id = AccountId::new("alice", "wonderland");
        let asset_definition_id = AssetDefinitionId::new("rose", "wonderland");
        let asset_id = AssetId::new(asset_definition_id, account_id);
        let mut store = Metadata::new();
        store
            .insert_with_limits(
                "Bytes".to_owned(),
                Value::Vec(vec![Value::U32(1), Value::U32(2), Value::U32(3)]),
                MetadataLimits::new(10, 100),
            )
            .unwrap();
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
            account.metadata.insert_with_limits(
                "Bytes".to_string(),
                Value::Vec(vec![Value::U32(1), Value::U32(2), Value::U32(3)]),
                MetadataLimits::new(10, 100),
            )?;
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

    #[tokio::test]
    async fn find_transaction() -> Result<()> {
        let domains = DomainsMap::new();
        let mut domain = Domain::new("wonderland");
        let account_id = AccountId::new("alice", "wonderland");
        let mut account = Account::new(account_id.clone());
        let key_pair = KeyPair::generate()?;
        account.signatories.push(key_pair.public_key.clone());
        domain.accounts.insert(account_id.clone(), account);
        let mut block = PendingBlock::new(Vec::new());
        domains.insert("wonderland".to_string(), domain);
        let world = World::with(domains, PeersIds::new());
        let wsv = WorldStateView::new(world);

        let trx = Transaction::new(vec![], account_id, 4000);
        let signed_trx = trx.sign(&key_pair)?;
        let vatrx = VersionedAcceptedTransaction::from_transaction(signed_trx, 4096)?;
        block.transactions.push(vatrx.clone());
        let vcb = block
            .chain_first()
            .validate(&wsv, &AllowAll.into(), &AllowAll.into())
            .sign(key_pair.clone())
            .expect("Failed to sign blocks.")
            .commit();
        wsv.apply(vcb).await;

        let result = FindTransactionByHash::new(Hash::from(vatrx.hash())).execute(&wsv)?;
        match result {
            TransactionValue::Transaction(trx) => assert_eq!(vatrx.hash(), trx.hash()),
            TransactionValue::RejectedTransaction(trx) => assert_eq!(vatrx.hash(), trx.hash()),
        }
        Ok(())
    }
}
