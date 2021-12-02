//! This module contains query related Iroha functionality.

use std::{error::Error as StdError, fmt};

use eyre::{eyre, Result};
use iroha_crypto::SignatureOf;
use iroha_data_model::{prelude::*, query};
use iroha_macro::Io;
use iroha_version::scale::DecodeVersioned;
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
    ) -> Result<ValidQueryRequest, Error> {
        let account_has_public_key = wsv
            .map_account(&self.payload.account_id, |account| {
                account.signatories.contains(&self.signature.public_key)
            })
            .map_err(Error::Find)?;
        if !account_has_public_key {
            return Err(Error::Signature(eyre!(
                "Public key used for the signature does not correspond to the account."
            )));
        }
        query_validator
            .check(&self.payload.account_id, &self.payload.query, wsv)
            .map_err(Error::Permission)?;
        Ok(ValidQueryRequest {
            query: self.payload.query,
        })
    }
}

impl TryFrom<SignedQueryRequest> for VerifiedQueryRequest {
    type Error = Error;

    fn try_from(query: SignedQueryRequest) -> Result<Self, Error> {
        query
            .signature
            .verify(&query.payload)
            .map(|_| Self {
                payload: query.payload,
                signature: query.signature,
            })
            .map_err(|e| Error::Signature(eyre!(e)))
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

/// Query errors.
#[derive(Error, Debug)]
pub enum Error {
    /// Query can not be decoded.
    #[error("Query can not be decoded")]
    Decode(#[source] Box<iroha_version::error::Error>),
    /// Query has unsupported version.
    #[error("Query has unsupported version")]
    Version(#[source] UnsupportedVersionError),
    /// Query has wrong signature.
    #[error("Query has wrong signature: {0}")]
    Signature(eyre::Error),
    /// Query is not allowed.
    #[error("Query is not allowed: {0}")]
    Permission(String),
    /// Query found nothing.
    #[error("Query found nothing: {0}")]
    Find(eyre::Error),
}

impl Error {
    /// Status code for query error response.
    pub const fn status_code(&self) -> StatusCode {
        use Error::*;
        match *self {
            Decode(_) | Version(_) => StatusCode::BAD_REQUEST,
            Signature(_) => StatusCode::UNAUTHORIZED,
            Permission(_) | Find(_) => StatusCode::NOT_FOUND,
        }
    }
}

impl Reply for Error {
    fn into_response(self) -> Response {
        reply::with_status(self.to_string(), self.status_code()).into_response()
    }
}
impl warp::reject::Reject for Error {}

impl TryFrom<&Bytes> for VerifiedQueryRequest {
    type Error = Error;
    fn try_from(body: &Bytes) -> Result<Self, Self::Error> {
        let query = VersionedSignedQueryRequest::decode_versioned(body.as_ref())
            .map_err(|e| Error::Decode(Box::new(e)))?;
        let VersionedSignedQueryRequest::V1(query) = query;
        VerifiedQueryRequest::try_from(query)
    }
}

impl<W: WorldTrait> ValidQuery<W> for QueryBox {
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
            FindDomainKeyValueByIdAndKey(query) => query.execute_into_value(wsv),
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
    use once_cell::sync::Lazy;

    use super::*;
    use crate::wsv::World;

    static ALICE_KEYS: Lazy<KeyPair> = Lazy::new(|| KeyPair::generate().unwrap());
    static ALICE_ID: Lazy<AccountId> = Lazy::new(|| AccountId::new("alice", "wonderland"));

    fn world_with_test_domains() -> World {
        let domains = DomainsMap::new();
        let mut domain = Domain::new("wonderland");
        let mut account = Account::new(ALICE_ID.clone());
        account.signatories.push(ALICE_KEYS.public_key.clone());
        domain.accounts.insert(ALICE_ID.clone(), account);
        let asset_definition_id = AssetDefinitionId::new("rose", "wonderland");
        domain.asset_definitions.insert(
            asset_definition_id.clone(),
            AssetDefinitionEntry::new(
                AssetDefinition::new(asset_definition_id, AssetValueType::Quantity, true),
                ALICE_ID.clone(),
            ),
        );
        domains.insert("wonderland".to_string(), domain);
        World::with(domains, PeersIds::new())
    }

    #[test]
    fn asset_store() -> Result<()> {
        let wsv = WorldStateView::new(world_with_test_domains());
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
        let wsv = WorldStateView::new(world_with_test_domains());
        wsv.modify_account(&ALICE_ID, |account| {
            account.metadata.insert_with_limits(
                "Bytes".to_string(),
                Value::Vec(vec![Value::U32(1), Value::U32(2), Value::U32(3)]),
                MetadataLimits::new(10, 100),
            )?;
            Ok(())
        })?;
        let bytes = FindAccountKeyValueByIdAndKey::new(ALICE_ID.clone(), "Bytes".to_owned())
            .execute(&wsv)?;
        assert_eq!(
            bytes,
            Value::Vec(vec![Value::U32(1), Value::U32(2), Value::U32(3)])
        );
        Ok(())
    }

    #[tokio::test]
    async fn find_transaction() -> Result<()> {
        let wsv = WorldStateView::new(world_with_test_domains());

        let tx = Transaction::new(vec![], ALICE_ID.clone(), 4000);
        let signed_tx = tx.sign(&ALICE_KEYS)?;
        let va_tx = VersionedAcceptedTransaction::from_transaction(signed_tx.clone(), 4096)?;

        let mut block = PendingBlock::new(Vec::new());
        block.transactions.push(va_tx.clone());
        let vcb = block
            .chain_first()
            .validate(&wsv, &AllowAll.into(), &AllowAll.into())
            .sign(ALICE_KEYS.clone())
            .expect("Failed to sign blocks.")
            .commit();
        wsv.apply(vcb).await?;

        let wrong_hash = Hash::new(&[2_u8]);
        let not_found = FindTransactionByHash::new(wrong_hash).execute(&wsv);
        assert!(matches!(not_found, Err(_)));

        let found_accepted = FindTransactionByHash::new(Hash::from(va_tx.hash())).execute(&wsv)?;
        match found_accepted {
            TransactionValue::Transaction(tx) => {
                assert_eq!(Hash::from(va_tx.hash()), Hash::from(tx.hash()))
            }
            TransactionValue::RejectedTransaction(_) => {}
        }
        Ok(())
    }

    #[test]
    fn domain_metadata() -> Result<()> {
        let wsv = WorldStateView::new(world_with_test_domains());
        let domain_name = "wonderland".to_owned();
        let key = "Bytes".to_owned();
        wsv.modify_domain(&domain_name, |domain| {
            domain.metadata.insert_with_limits(
                key.clone(),
                Value::Vec(vec![Value::U32(1), Value::U32(2), Value::U32(3)]),
                MetadataLimits::new(10, 100),
            )?;
            Ok(())
        })?;
        let bytes = FindDomainKeyValueByIdAndKey::new(domain_name, key).execute(&wsv)?;
        assert_eq!(
            bytes,
            Value::Vec(vec![Value::U32(1), Value::U32(2), Value::U32(3)])
        );
        Ok(())
    }
}
