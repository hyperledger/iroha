//! Query functionality. The common error type is also defined here,
//! alongside functions for converting them into HTTP responses.
#![allow(
    clippy::arithmetic_side_effects,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc
)]
use eyre::Result;
use iroha_data_model::{prelude::*, query::error::QueryExecutionFail as Error};
use parity_scale_codec::{Decode, Encode};

use crate::{prelude::ValidQuery, WorldStateView};

/// Represents lazy evaluated query output
pub trait Lazy {
    /// Type of the lazy evaluated query output
    type Lazy<'a>;
}

/// Lazily evaluated equivalent of [`Value`]
pub enum LazyValue<'a> {
    /// Concrete computed [`Value`]
    Value(Value),
    /// Iterator over a set of [`Value`]s
    Iter(Box<dyn Iterator<Item = Value> + 'a>),
}

impl Lazy for Value {
    type Lazy<'a> = LazyValue<'a>;
}

impl<T> Lazy for Vec<T> {
    type Lazy<'a> = Box<dyn Iterator<Item = T> + 'a>;
}

macro_rules! impl_lazy {
    ( $($ident:ty),+ $(,)? ) => { $(
        impl Lazy for $ident {
            type Lazy<'a> = Self;
        } )+
    };
}
impl_lazy! {
    bool,
    iroha_data_model::numeric::NumericValue,
    iroha_data_model::role::Role,
    iroha_data_model::asset::Asset,
    iroha_data_model::asset::AssetDefinition,
    iroha_data_model::account::Account,
    iroha_data_model::domain::Domain,
    iroha_data_model::block::BlockHeader,
    iroha_data_model::query::MetadataValue,
    iroha_data_model::query::TransactionQueryOutput,
    iroha_data_model::permission::PermissionTokenSchema,
    iroha_data_model::trigger::Trigger<iroha_data_model::events::TriggeringFilterBox, iroha_data_model::trigger::OptimizedExecutable>,
}

/// Query Request statefully validated on the Iroha node side.
#[derive(Debug, Decode, Encode)]
#[repr(transparent)]
pub struct ValidQueryRequest(VersionedSignedQuery);

impl ValidQueryRequest {
    /// Validate query.
    ///
    /// # Errors
    /// - Account doesn't exist
    /// - Account doesn't have the correct public key
    /// - Account has incorrect permissions
    pub fn validate(
        query: VersionedSignedQuery,
        wsv: &WorldStateView,
    ) -> Result<Self, ValidationFail> {
        let account_has_public_key = wsv
            .map_account(query.authority(), |account| {
                account.signatories.contains(query.signature().public_key())
            })
            .map_err(Error::from)?;
        if !account_has_public_key {
            return Err(Error::Signature(String::from(
                "Signature public key doesn't correspond to the account.",
            ))
            .into());
        }
        wsv.validator()
            .validate_query(wsv, query.authority(), query.query().clone())?;
        Ok(Self(query))
    }

    /// Execute contained query on the [`WorldStateView`].
    ///
    /// # Errors
    /// Forwards `self.query.execute` error.
    pub fn execute<'wsv>(&'wsv self, wsv: &'wsv WorldStateView) -> Result<LazyValue<'wsv>, Error> {
        let value = self.0.query().execute(wsv)?;

        Ok(if let LazyValue::Iter(iter) = value {
            LazyValue::Iter(Box::new(iter.filter(|val| self.0.filter().applies(val))))
        } else {
            value
        })

        // We're not handling the LimitedMetadata case, because
        // the predicate when applied to it is ambiguous. We could
        // pattern match on that case, but we should assume that
        // metadata (since it's limited) isn't going to be too
        // difficult to filter client-side. I actually think that
        // Metadata should be restricted in what types it can
        // contain.
    }
}

impl ValidQuery for QueryBox {
    fn execute<'wsv>(&self, wsv: &'wsv WorldStateView) -> Result<LazyValue<'wsv>, Error> {
        iroha_logger::debug!(query=%self, "Executing");

        macro_rules! match_all {
            ( non_iter: {$( $non_iter_query:ident ),+ $(,)?} $( $query:ident, )+ ) => {
                match self { $(
                    QueryBox::$non_iter_query(query) => query.execute(wsv).map(Value::from).map(LazyValue::Value), )+ $(
                    QueryBox::$query(query) => query.execute(wsv).map(|i| i.map(Value::from)).map(|iter| LazyValue::Iter(Box::new(iter))), )+
                }
            };
        }

        match_all! {
            non_iter: {
                FindAccountById,
                FindAssetById,
                FindAssetDefinitionById,
                FindAssetQuantityById,
                FindTotalAssetQuantityByAssetDefinitionId,
                IsAssetDefinitionOwner,
                FindDomainById,
                FindBlockHeaderByHash,
                FindTransactionByHash,
                FindTriggerById,
                FindRoleByRoleId,
                FindDomainKeyValueByIdAndKey,
                FindAssetKeyValueByIdAndKey,
                FindAccountKeyValueByIdAndKey,
                FindAssetDefinitionKeyValueByIdAndKey,
                FindTriggerKeyValueByIdAndKey,
                FindPermissionTokenSchema,
            }

            FindAllAccounts,
            FindAccountsByName,
            FindAccountsByDomainId,
            FindAccountsWithAsset,
            FindAllAssets,
            FindAllAssetsDefinitions,
            FindAssetsByName,
            FindAssetsByAccountId,
            FindAssetsByAssetDefinitionId,
            FindAssetsByDomainId,
            FindAssetsByDomainIdAndAssetDefinitionId,
            FindAllDomains,
            FindAllPeers,
            FindAllBlocks,
            FindAllBlockHeaders,
            FindAllTransactions,
            FindTransactionsByAccountId,
            FindPermissionTokensByAccountId,
            FindAllActiveTriggerIds,
            FindTriggersByDomainId,
            FindAllRoles,
            FindAllRoleIds,
            FindRolesByAccountId,
            FindAllParameters,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    use std::str::FromStr as _;

    use iroha_crypto::{Hash, HashOf, KeyPair};
    use iroha_data_model::{query::error::FindError, transaction::TransactionLimits};
    use once_cell::sync::Lazy;

    use super::*;
    use crate::{
        block::*, kura::Kura, smartcontracts::isi::Registrable as _,
        sumeragi::network_topology::Topology, tx::AcceptedTransaction, wsv::World, PeersIds,
    };

    static ALICE_KEYS: Lazy<KeyPair> = Lazy::new(|| KeyPair::generate().unwrap());
    static ALICE_ID: Lazy<AccountId> =
        Lazy::new(|| AccountId::from_str("alice@wonderland").expect("Valid"));

    fn world_with_test_domains() -> World {
        let domain_id = DomainId::from_str("wonderland").expect("Valid");
        let mut domain = Domain::new(domain_id).build(&ALICE_ID);
        let account =
            Account::new(ALICE_ID.clone(), [ALICE_KEYS.public_key().clone()]).build(&ALICE_ID);
        assert!(domain.add_account(account).is_none());
        let asset_definition_id = AssetDefinitionId::from_str("rose#wonderland").expect("Valid");
        assert!(domain
            .add_asset_definition(AssetDefinition::quantity(asset_definition_id).build(&ALICE_ID))
            .is_none());
        World::with([domain], PeersIds::new())
    }

    fn world_with_test_asset_with_metadata() -> World {
        let asset_definition_id = AssetDefinitionId::from_str("rose#wonderland").expect("Valid");
        let mut domain =
            Domain::new(DomainId::from_str("wonderland").expect("Valid")).build(&ALICE_ID);
        let mut account =
            Account::new(ALICE_ID.clone(), [ALICE_KEYS.public_key().clone()]).build(&ALICE_ID);
        assert!(domain
            .add_asset_definition(
                AssetDefinition::quantity(asset_definition_id.clone()).build(&ALICE_ID)
            )
            .is_none());

        let mut store = Metadata::new();
        store
            .insert_with_limits(
                Name::from_str("Bytes").expect("Valid"),
                Value::Vec(vec![1_u32.to_value(), 2_u32.to_value(), 3_u32.to_value()]),
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
            Value::Vec(vec![1_u32.to_value(), 2_u32.to_value(), 3_u32.to_value()]),
            MetadataLimits::new(10, 100),
        )?;

        let mut domain = Domain::new(DomainId::from_str("wonderland")?).build(&ALICE_ID);
        let account = Account::new(ALICE_ID.clone(), [ALICE_KEYS.public_key().clone()])
            .with_metadata(metadata)
            .build(&ALICE_ID);
        assert!(domain.add_account(account).is_none());
        let asset_definition_id = AssetDefinitionId::from_str("rose#wonderland").expect("Valid");
        assert!(domain
            .add_asset_definition(AssetDefinition::quantity(asset_definition_id).build(&ALICE_ID))
            .is_none());
        Ok(World::with([domain], PeersIds::new()))
    }

    fn wsv_with_test_blocks_and_transactions(
        blocks: u64,
        valid_tx_per_block: usize,
        invalid_tx_per_block: usize,
    ) -> Result<WorldStateView> {
        let kura = Kura::blank_kura_for_testing();
        let mut wsv = WorldStateView::new(world_with_test_domains(), kura.clone());

        let limits = TransactionLimits {
            max_instruction_number: 1,
            max_wasm_size_bytes: 0,
        };
        let huge_limits = TransactionLimits {
            max_instruction_number: 1000,
            max_wasm_size_bytes: 0,
        };

        wsv.config.transaction_limits = limits;

        let valid_tx = {
            let instructions: [InstructionBox; 0] = [];
            let tx = TransactionBuilder::new(ALICE_ID.clone())
                .with_instructions(instructions)
                .sign(ALICE_KEYS.clone())?;
            AcceptedTransaction::accept(tx, &limits)?
        };
        let invalid_tx = {
            let isi = FailBox::new("fail");
            let tx = TransactionBuilder::new(ALICE_ID.clone())
                .with_instructions([isi.clone(), isi])
                .sign(ALICE_KEYS.clone())?;
            AcceptedTransaction::accept(tx, &huge_limits)?
        };

        let mut transactions = vec![valid_tx; valid_tx_per_block];
        transactions.append(&mut vec![invalid_tx; invalid_tx_per_block]);

        let topology = Topology::new(vec![]);
        let first_block = BlockBuilder::new(transactions.clone(), topology.clone(), Vec::new())
            .chain_first(&mut wsv)
            .sign(ALICE_KEYS.clone())?
            .commit(&topology)
            .expect("Block is valid");

        wsv.apply(&first_block)?;
        kura.store_block(first_block);

        for _ in 1u64..blocks {
            let block = BlockBuilder::new(transactions.clone(), topology.clone(), Vec::new())
                .chain(0, &mut wsv)
                .sign(ALICE_KEYS.clone())?
                .commit(&topology)
                .expect("Block is valid");

            wsv.apply(&block)?;
            kura.store_block(block);
        }

        Ok(wsv)
    }

    #[test]
    fn asset_store() -> Result<()> {
        let kura = Kura::blank_kura_for_testing();
        let wsv = WorldStateView::new(world_with_test_asset_with_metadata(), kura);

        let asset_definition_id = AssetDefinitionId::from_str("rose#wonderland")?;
        let asset_id = AssetId::new(asset_definition_id, ALICE_ID.clone());
        let bytes =
            FindAssetKeyValueByIdAndKey::new(asset_id, Name::from_str("Bytes")?).execute(&wsv)?;
        assert_eq!(
            Value::Vec(vec![1_u32.to_value(), 2_u32.to_value(), 3_u32.to_value()]),
            bytes.into(),
        );
        Ok(())
    }

    #[test]
    fn account_metadata() -> Result<()> {
        let kura = Kura::blank_kura_for_testing();
        let wsv = WorldStateView::new(world_with_test_account_with_metadata()?, kura);

        let bytes = FindAccountKeyValueByIdAndKey::new(ALICE_ID.clone(), Name::from_str("Bytes")?)
            .execute(&wsv)?;
        assert_eq!(
            Value::Vec(vec![1_u32.to_value(), 2_u32.to_value(), 3_u32.to_value()]),
            bytes.into(),
        );
        Ok(())
    }

    #[test]
    fn find_all_blocks() -> Result<()> {
        let num_blocks = 100;

        let wsv = wsv_with_test_blocks_and_transactions(num_blocks, 1, 1)?;
        let blocks = FindAllBlocks.execute(&wsv)?.collect::<Vec<_>>();

        assert_eq!(blocks.len() as u64, num_blocks);
        assert!(blocks.windows(2).all(|wnd| wnd[0] >= wnd[1]));

        Ok(())
    }

    #[test]
    fn find_all_block_headers() -> Result<()> {
        let num_blocks = 100;

        let wsv = wsv_with_test_blocks_and_transactions(num_blocks, 1, 1)?;
        let block_headers = FindAllBlockHeaders.execute(&wsv)?.collect::<Vec<_>>();

        assert_eq!(block_headers.len() as u64, num_blocks);
        assert!(block_headers.windows(2).all(|wnd| wnd[0] >= wnd[1]));

        Ok(())
    }

    #[test]
    fn find_block_header_by_hash() -> Result<()> {
        let wsv = wsv_with_test_blocks_and_transactions(1, 1, 1)?;
        let block = wsv.all_blocks().last().expect("WSV is empty");

        assert_eq!(
            FindBlockHeaderByHash::new(block.hash()).execute(&wsv)?,
            block.payload().header
        );

        assert!(
            FindBlockHeaderByHash::new(HashOf::from_untyped_unchecked(Hash::new([42])))
                .execute(&wsv)
                .is_err()
        );

        Ok(())
    }

    #[test]
    fn find_all_transactions() -> Result<()> {
        let num_blocks = 100;

        let wsv = wsv_with_test_blocks_and_transactions(num_blocks, 1, 1)?;
        let txs = FindAllTransactions.execute(&wsv)?.collect::<Vec<_>>();

        assert_eq!(txs.len() as u64, num_blocks * 2);
        assert_eq!(
            txs.iter()
                .filter(|txn| txn.transaction.error.is_some())
                .count() as u64,
            num_blocks
        );
        assert_eq!(
            txs.iter()
                .filter(|txn| txn.transaction.error.is_none())
                .count() as u64,
            num_blocks
        );

        Ok(())
    }

    #[test]
    fn find_transaction() -> Result<()> {
        let kura = Kura::blank_kura_for_testing();
        let mut wsv = WorldStateView::new(world_with_test_domains(), kura.clone());

        let instructions: [InstructionBox; 0] = [];
        let tx = TransactionBuilder::new(ALICE_ID.clone())
            .with_instructions(instructions)
            .sign(ALICE_KEYS.clone())?;

        let tx_limits = &wsv.transaction_validator().transaction_limits;
        let va_tx = AcceptedTransaction::accept(tx, tx_limits)?;

        let topology = Topology::new(vec![]);
        let vcb = BlockBuilder::new(vec![va_tx.clone()], topology.clone(), Vec::new())
            .chain_first(&mut wsv)
            .sign(ALICE_KEYS.clone())?
            .commit(&topology)
            .expect("Block is valid");

        wsv.apply(&vcb)?;
        kura.store_block(vcb);

        let unapplied_tx = TransactionBuilder::new(ALICE_ID.clone())
            .with_instructions([UnregisterBox::new(
                "account@domain".parse::<AccountId>().unwrap(),
            )])
            .sign(ALICE_KEYS.clone())?;
        let wrong_hash = unapplied_tx.hash();
        let not_found = FindTransactionByHash::new(wrong_hash).execute(&wsv);
        assert!(matches!(
            not_found,
            Err(Error::Find(FindError::Transaction(_)))
        ));

        let found_accepted = FindTransactionByHash::new(va_tx.hash()).execute(&wsv)?;
        if found_accepted.transaction.error.is_none() {
            assert_eq!(va_tx.hash(), found_accepted.transaction.hash())
        }
        Ok(())
    }

    #[test]
    fn domain_metadata() -> Result<()> {
        let kura = Kura::blank_kura_for_testing();
        let wsv = {
            let mut metadata = Metadata::new();
            metadata.insert_with_limits(
                Name::from_str("Bytes")?,
                Value::Vec(vec![1_u32.to_value(), 2_u32.to_value(), 3_u32.to_value()]),
                MetadataLimits::new(10, 100),
            )?;
            let mut domain = Domain::new(DomainId::from_str("wonderland")?)
                .with_metadata(metadata)
                .build(&ALICE_ID);
            let account =
                Account::new(ALICE_ID.clone(), [ALICE_KEYS.public_key().clone()]).build(&ALICE_ID);
            assert!(domain.add_account(account).is_none());
            let asset_definition_id = AssetDefinitionId::from_str("rose#wonderland")?;
            assert!(domain
                .add_asset_definition(
                    AssetDefinition::quantity(asset_definition_id).build(&ALICE_ID)
                )
                .is_none());
            WorldStateView::new(World::with([domain], PeersIds::new()), kura)
        };

        let domain_id = DomainId::from_str("wonderland")?;
        let key = Name::from_str("Bytes")?;
        let bytes = FindDomainKeyValueByIdAndKey::new(domain_id, key).execute(&wsv)?;
        assert_eq!(
            Value::Vec(vec![1_u32.to_value(), 2_u32.to_value(), 3_u32.to_value()]),
            bytes.into(),
        );
        Ok(())
    }
}
