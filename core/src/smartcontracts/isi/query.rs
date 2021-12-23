//! Query related Iroha functionality.

use std::{error::Error as StdError, fmt};

use eyre::{eyre, Result};
use iroha_crypto::SignatureOf;
use iroha_data_model::{prelude::*, query};
use iroha_version::scale::DecodeVersioned;
use parity_scale_codec::{Decode, Encode};
use thiserror::Error;
use warp::{
    http::StatusCode,
    hyper::body::Bytes,
    reply::{self, Response},
    Reply,
};

use super::{permissions::IsQueryAllowedBoxed, FindError};
use crate::{prelude::*, WorldTrait};

/// Query Request verified on the Iroha node side.
#[derive(Debug, Decode, Encode)]
pub struct VerifiedQueryRequest {
    /// Payload.
    payload: query::Payload,
    /// Signature of the client who sends this query.
    signature: SignatureOf<query::Payload>,
}

impl VerifiedQueryRequest {
    /// Statefully validate query.
    ///
    /// # Errors
    /// if:
    /// - Account doesn't exist.
    /// - Account doesn't have the correct public key.
    /// - Account has the correct permissions.
    pub fn validate<W: WorldTrait>(
        self,
        wsv: &WorldStateView<W>,
        query_validator: &IsQueryAllowedBoxed<W>,
    ) -> Result<ValidQueryRequest, Error> {
        let account_has_public_key = wsv.map_account(&self.payload.account_id, |account| {
            account.signatories.contains(&self.signature.public_key)
        })?;
        if !account_has_public_key {
            return Err(Error::Signature(eyre!(
                "Signature public key doesn't correspond to the account."
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
#[derive(Debug, Decode, Encode)]
pub struct ValidQueryRequest {
    query: QueryBox,
}

impl ValidQueryRequest {
    /// Execute contained query on the [`WorldStateView`].
    ///
    /// # Errors
    /// Forwards `self.query.execute` error.
    #[inline]
    pub fn execute<W: WorldTrait>(&self, wsv: &WorldStateView<W>) -> Result<Value, Error> {
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
    Find(#[source] Box<FindError>),
    /// Evaluate
    #[error("Evaluation failed. {0}")]
    Evaluate(#[source] eyre::Report),
    /// Conversion failures
    #[error("Conversion failed")]
    Conversion(#[source] eyre::Report),
}

impl From<FindError> for Error {
    fn from(err: FindError) -> Self {
        Error::Find(Box::new(err))
    }
}

impl Error {
    /// Status code for query error response.
    pub const fn status_code(&self) -> StatusCode {
        use Error::*;
        match *self {
            Conversion(_) | Decode(_) | Version(_) => StatusCode::BAD_REQUEST,
            Signature(_) => StatusCode::UNAUTHORIZED,
            Evaluate(_) | Permission(_) | Find(_) => StatusCode::NOT_FOUND,
        }
    }
}

impl Reply for Error {
    #[inline]
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
    fn execute(&self, wsv: &WorldStateView<W>) -> Result<Value, Error> {
        use QueryBox::*;

        match self {
            FindAllAccounts(query) => query.execute_into_value(wsv),
            FindAccountById(query) => query.execute_into_value(wsv),
            FindAccountsByName(query) => query.execute_into_value(wsv),
            FindAccountsByDomainId(query) => query.execute_into_value(wsv),
            FindAllAssets(query) => query.execute_into_value(wsv),
            FindAllAssetsDefinitions(query) => query.execute_into_value(wsv),
            FindAssetById(query) => query.execute_into_value(wsv),
            FindAssetsByName(query) => query.execute_into_value(wsv),
            FindAssetsByAccountId(query) => query.execute_into_value(wsv),
            FindAssetsByAssetDefinitionId(query) => query.execute_into_value(wsv),
            FindAssetsByDomainId(query) => query.execute_into_value(wsv),
            FindAssetsByDomainIdAndAssetDefinitionId(query) => query.execute_into_value(wsv),
            FindAssetQuantityById(query) => query.execute_into_value(wsv),
            FindAllDomains(query) => query.execute_into_value(wsv),
            FindDomainById(query) => query.execute_into_value(wsv),
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
    static ALICE_ID: Lazy<AccountId> = Lazy::new(|| AccountId::test("alice", "wonderland"));

    fn world_with_test_domains() -> World {
        let domains = DomainsMap::new();
        let mut domain = Domain::test("wonderland");
        let mut account = Account::new(ALICE_ID.clone());
        account.signatories.push(ALICE_KEYS.public_key.clone());
        domain.accounts.insert(ALICE_ID.clone(), account);
        let asset_definition_id = AssetDefinitionId::test("rose", "wonderland");
        domain.asset_definitions.insert(
            asset_definition_id.clone(),
            AssetDefinitionEntry::new(
                AssetDefinition::new(asset_definition_id, AssetValueType::Quantity, true),
                ALICE_ID.clone(),
            ),
        );
        domains.insert(DomainId::test("wonderland"), domain);
        World::with(domains, PeersIds::new())
    }

    #[test]
    fn asset_store() -> Result<()> {
        let wsv = WorldStateView::new(world_with_test_domains());
        let account_id = AccountId::test("alice", "wonderland");
        let asset_definition_id = AssetDefinitionId::test("rose", "wonderland");
        let asset_id = AssetId::new(asset_definition_id, account_id);
        let mut store = Metadata::new();
        store
            .insert_with_limits(
                Name::test("Bytes"),
                Value::Vec(vec![Value::U32(1), Value::U32(2), Value::U32(3)]),
                MetadataLimits::new(10, 100),
            )
            .unwrap();
        wsv.add_asset(Asset::new(asset_id.clone(), AssetValue::Store(store)))?;
        let bytes =
            FindAssetKeyValueByIdAndKey::new(asset_id, Name::test("Bytes")).execute(&wsv)?;
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
                Name::test("Bytes"),
                Value::Vec(vec![Value::U32(1), Value::U32(2), Value::U32(3)]),
                MetadataLimits::new(10, 100),
            )?;
            Ok(())
        })?;
        let bytes = FindAccountKeyValueByIdAndKey::new(ALICE_ID.clone(), Name::test("Bytes"))
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
        let domain_id = DomainId::test("wonderland");
        let key = Name::test("Bytes");
        wsv.modify_domain(&domain_id, |domain| {
            domain.metadata.insert_with_limits(
                key.clone(),
                Value::Vec(vec![Value::U32(1), Value::U32(2), Value::U32(3)]),
                MetadataLimits::new(10, 100),
            )?;
            Ok(())
        })?;
        let bytes = FindDomainKeyValueByIdAndKey::new(domain_id, key).execute(&wsv)?;
        assert_eq!(
            bytes,
            Value::Vec(vec![Value::U32(1), Value::U32(2), Value::U32(3)])
        );
        Ok(())
    }
}
