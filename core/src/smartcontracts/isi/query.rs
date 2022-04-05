//! Query functionality. This module defines the
//! `VerifiedQueryRequest`, which is the only kind of query that is
//! permitted to execute.  The common error type is also defined here,
//! alongside functions for converting them into HTTP responses.

use std::{error::Error as StdError, fmt};

use eyre::Result;
use iroha_crypto::SignatureOf;
use iroha_data_model::{prelude::*, query};
use iroha_schema::IntoSchema;
use iroha_version::scale::DecodeVersioned;
use parity_scale_codec::{Decode, Encode};
use thiserror::Error;
use warp::{http::StatusCode, hyper::body::Bytes};

use super::{permissions::IsQueryAllowedBoxed, FindError};
use crate::{prelude::ValidQuery, WorldStateView, WorldTrait};

/// Query Request verified on the Iroha node side.
#[derive(Debug, Decode, Encode)]
pub struct VerifiedQueryRequest {
    /// Payload.
    payload: query::Payload,
    /// Signature of the client who sends this query.
    signature: SignatureOf<query::Payload>,
}

impl VerifiedQueryRequest {
    /// Validate query.
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
            account.contains_signatory(&self.signature.public_key)
        })?;
        if !account_has_public_key {
            return Err(Error::Signature(String::from(
                "Signature public key doesn't correspond to the account.",
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
            .map_err(|e| Error::Signature(e.to_string()))
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
#[derive(Clone, Copy, Eq, PartialEq, Debug, Decode, Encode, IntoSchema)]
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
#[derive(Error, Debug, Clone, Decode, Encode, IntoSchema)]
pub enum Error {
    /// Query can not be decoded.
    #[error("Query can not be decoded")]
    Decode(#[source] Box<iroha_version::error::Error>),
    /// Query has unsupported version.
    #[error("Query has unsupported version")]
    Version(#[source] UnsupportedVersionError),
    /// Query has wrong signature.
    #[error("Query has wrong signature: {0}")]
    Signature(String),
    /// Query is not allowed.
    #[error("Query is not allowed: {0}")]
    Permission(String),
    /// Query has wrong expression.
    #[error("Query has wrong expression: {0}")]
    Evaluate(String),
    /// Query found nothing.
    #[error("Query found nothing: {0}")]
    Find(#[source] Box<FindError>),
    /// Query found wrong type of asset.
    #[error("Query found wrong type of asset: {0}")]
    Conversion(String),
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
        match self {
            Decode(_) | Version(_) | Evaluate(_) | Conversion(_) => StatusCode::BAD_REQUEST,
            Signature(_) => StatusCode::UNAUTHORIZED,
            Permission(_) => StatusCode::FORBIDDEN,
            Find(_) => StatusCode::NOT_FOUND,
        }
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
    fn execute(&self, wsv: &WorldStateView<W>) -> Result<Self::Output, Error> {
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

    use std::{str::FromStr, sync::Arc};

    use iroha_crypto::{Hash, KeyPair};
    use iroha_data_model::transaction::TransactionLimits;
    use once_cell::sync::Lazy;

    use super::*;
    use crate::{
        block::PendingBlock, prelude::AllowAll, tx::TransactionValidator, wsv::World, PeersIds,
    };

    static ALICE_KEYS: Lazy<KeyPair> = Lazy::new(|| KeyPair::generate().unwrap());
    static ALICE_ID: Lazy<AccountId> =
        Lazy::new(|| AccountId::from_str("alice@wonderland").expect("Valid"));

    fn world_with_test_domains() -> World {
        let domain_id = DomainId::from_str("wonderland").expect("Valid");
        let mut domain = Domain::new(domain_id).build();
        let account = Account::new(ALICE_ID.clone(), [ALICE_KEYS.public_key.clone()]).build();
        assert!(domain.add_account(account).is_none());
        let asset_definition_id = AssetDefinitionId::from_str("rose#wonderland").expect("Valid");
        assert!(domain
            .add_asset_definition(
                AssetDefinition::quantity(asset_definition_id).build(),
                ALICE_ID.clone(),
            )
            .is_none());
        World::with([domain], PeersIds::new())
    }

    fn world_with_test_asset_with_metadata() -> World {
        let asset_definition_id = AssetDefinitionId::from_str("rose#wonderland").expect("Valid");
        let mut domain = Domain::new(DomainId::from_str("wonderland").expect("Valid")).build();
        let mut account = Account::new(ALICE_ID.clone(), [ALICE_KEYS.public_key.clone()]).build();
        assert!(domain
            .add_asset_definition(
                AssetDefinition::quantity(asset_definition_id.clone()).build(),
                ALICE_ID.clone(),
            )
            .is_none());

        let mut store = Metadata::new();
        store
            .insert_with_limits(
                Name::from_str("Bytes").expect("Valid"),
                Value::Vec(vec![Value::U32(1), Value::U32(2), Value::U32(3)]),
                MetadataLimits::new(10, 100),
            )
            .unwrap();
        let asset_id = AssetId::new(asset_definition_id, account.id().clone());
        let asset = Asset::new(asset_id, AssetValue::Store(store));

        assert!(account.add_asset(asset).is_none());
        assert!(domain.add_account(account).is_none());
        World::with([domain], PeersIds::new())
    }

    fn world_with_test_account_with_metadata() -> Result<World> {
        let mut metadata = Metadata::new();
        metadata.insert_with_limits(
            Name::from_str("Bytes")?,
            Value::Vec(vec![Value::U32(1), Value::U32(2), Value::U32(3)]),
            MetadataLimits::new(10, 100),
        )?;

        let mut domain = Domain::new(DomainId::from_str("wonderland")?).build();
        let account = Account::new(ALICE_ID.clone(), [ALICE_KEYS.public_key.clone()])
            .with_metadata(metadata)
            .build();
        assert!(domain.add_account(account).is_none());
        let asset_definition_id = AssetDefinitionId::from_str("rose#wonderland").expect("Valid");
        assert!(domain
            .add_asset_definition(
                AssetDefinition::quantity(asset_definition_id).build(),
                ALICE_ID.clone(),
            )
            .is_none());
        Ok(World::with([domain], PeersIds::new()))
    }

    #[test]
    fn asset_store() -> Result<()> {
        let wsv = WorldStateView::new(world_with_test_asset_with_metadata());

        let asset_definition_id = AssetDefinitionId::from_str("rose#wonderland")?;
        let asset_id = AssetId::new(asset_definition_id, ALICE_ID.clone());
        let bytes =
            FindAssetKeyValueByIdAndKey::new(asset_id, Name::from_str("Bytes")?).execute(&wsv)?;
        assert_eq!(
            bytes,
            Value::Vec(vec![Value::U32(1), Value::U32(2), Value::U32(3)])
        );
        Ok(())
    }

    #[test]
    fn account_metadata() -> Result<()> {
        let wsv = WorldStateView::new(world_with_test_account_with_metadata()?);

        let bytes = FindAccountKeyValueByIdAndKey::new(ALICE_ID.clone(), Name::from_str("Bytes")?)
            .execute(&wsv)?;
        assert_eq!(
            bytes,
            Value::Vec(vec![Value::U32(1), Value::U32(2), Value::U32(3)])
        );
        Ok(())
    }

    #[tokio::test]
    async fn find_transaction() -> Result<()> {
        let wsv = Arc::new(WorldStateView::new(world_with_test_domains()));

        let tx = Transaction::new(ALICE_ID.clone(), Vec::<Instruction>::new().into(), 4000);
        let signed_tx = tx.sign(ALICE_KEYS.clone())?;

        let tx_limits = TransactionLimits {
            max_instruction_number: 4096,
            max_wasm_size_bytes: 0,
        };

        let va_tx =
            crate::VersionedAcceptedTransaction::from_transaction(signed_tx.clone(), &tx_limits)?;

        let mut block = PendingBlock::new(Vec::new(), Vec::new());
        block.transactions.push(va_tx.clone());
        let vcb = block
            .chain_first()
            .validate(&TransactionValidator::new(
                tx_limits,
                AllowAll::new(),
                AllowAll::new(),
                Arc::clone(&wsv),
            ))
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
        let wsv = {
            let mut metadata = Metadata::new();
            metadata.insert_with_limits(
                Name::from_str("Bytes")?,
                Value::Vec(vec![Value::U32(1), Value::U32(2), Value::U32(3)]),
                MetadataLimits::new(10, 100),
            )?;
            let mut domain = Domain::new(DomainId::from_str("wonderland")?)
                .with_metadata(metadata)
                .build();
            let account = Account::new(ALICE_ID.clone(), [ALICE_KEYS.public_key.clone()]).build();
            assert!(domain.add_account(account).is_none());
            let asset_definition_id = AssetDefinitionId::from_str("rose#wonderland")?;
            assert!(domain
                .add_asset_definition(
                    AssetDefinition::quantity(asset_definition_id).build(),
                    ALICE_ID.clone(),
                )
                .is_none());
            WorldStateView::new(World::with([domain], PeersIds::new()))
        };

        let domain_id = DomainId::from_str("wonderland")?;
        let key = Name::from_str("Bytes")?;
        let bytes = FindDomainKeyValueByIdAndKey::new(domain_id, key).execute(&wsv)?;
        assert_eq!(
            bytes,
            Value::Vec(vec![Value::U32(1), Value::U32(2), Value::U32(3)])
        );
        Ok(())
    }
}
