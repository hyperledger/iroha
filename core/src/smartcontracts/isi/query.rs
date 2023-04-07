//! Query functionality. The common error type is also defined here,
//! alongside functions for converting them into HTTP responses.
#![allow(
    clippy::arithmetic_side_effects,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc
)]
use eyre::Result;
use iroha_data_model::{prelude::*, query::error::QueryExecutionFailure as Error};
use parity_scale_codec::{Decode, Encode};

use crate::{prelude::ValidQuery, WorldStateView};

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
    pub fn execute(&self, wsv: &WorldStateView) -> Result<Value, Error> {
        self.query.execute(wsv)
    }

    /// Construct `ValidQueryRequest` from a validated query
    #[must_use]
    pub const fn new(query: QueryBox) -> Self {
        Self { query }
    }
}

impl ValidQuery for QueryBox {
    fn execute(&self, wsv: &WorldStateView) -> Result<Self::Output, Error> {
        use QueryBox::*;

        match self {
            FindAllAccounts(query) => query.execute_into_value(wsv),
            FindAccountById(query) => query.execute_into_value(wsv),
            FindAccountsByName(query) => query.execute_into_value(wsv),
            FindAccountsByDomainId(query) => query.execute_into_value(wsv),
            FindAccountsWithAsset(query) => query.execute_into_value(wsv),
            FindAllAssets(query) => query.execute_into_value(wsv),
            FindAllAssetsDefinitions(query) => query.execute_into_value(wsv),
            FindAssetById(query) => query.execute_into_value(wsv),
            FindAssetDefinitionById(query) => query.execute_into_value(wsv),
            FindAssetsByName(query) => query.execute_into_value(wsv),
            FindAssetsByAccountId(query) => query.execute_into_value(wsv),
            FindAssetsByAssetDefinitionId(query) => query.execute_into_value(wsv),
            FindAssetsByDomainId(query) => query.execute_into_value(wsv),
            FindAssetsByDomainIdAndAssetDefinitionId(query) => query.execute_into_value(wsv),
            FindAssetQuantityById(query) => query.execute_into_value(wsv),
            FindTotalAssetQuantityByAssetDefinitionId(query) => query.execute_into_value(wsv),
            IsAssetDefinitionOwner(query) => query.execute_into_value(wsv),
            FindAllDomains(query) => query.execute_into_value(wsv),
            FindDomainById(query) => query.execute_into_value(wsv),
            FindDomainKeyValueByIdAndKey(query) => query.execute_into_value(wsv),
            FindAllPeers(query) => query.execute_into_value(wsv),
            FindAssetKeyValueByIdAndKey(query) => query.execute_into_value(wsv),
            FindAccountKeyValueByIdAndKey(query) => query.execute_into_value(wsv),
            FindAllBlocks(query) => query.execute_into_value(wsv),
            FindAllBlockHeaders(query) => query.execute_into_value(wsv),
            FindBlockHeaderByHash(query) => query.execute_into_value(wsv),
            FindAllTransactions(query) => query.execute_into_value(wsv),
            FindTransactionsByAccountId(query) => query.execute_into_value(wsv),
            FindTransactionByHash(query) => query.execute_into_value(wsv),
            FindPermissionTokensByAccountId(query) => query.execute_into_value(wsv),
            FindAllPermissionTokenDefinitions(query) => query.execute_into_value(wsv),
            DoesAccountHavePermissionToken(query) => query.execute_into_value(wsv),
            FindAssetDefinitionKeyValueByIdAndKey(query) => query.execute_into_value(wsv),
            FindAllActiveTriggerIds(query) => query.execute_into_value(wsv),
            FindTriggerById(query) => query.execute_into_value(wsv),
            FindTriggerKeyValueByIdAndKey(query) => query.execute_into_value(wsv),
            FindTriggersByDomainId(query) => query.execute_into_value(wsv),
            FindAllRoles(query) => query.execute_into_value(wsv),
            FindAllRoleIds(query) => query.execute_into_value(wsv),
            FindRolesByAccountId(query) => query.execute_into_value(wsv),
            FindRoleByRoleId(query) => query.execute_into_value(wsv),
            FindAllParameters(query) => query.execute_into_value(wsv),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    use std::str::FromStr;

    use iroha_crypto::{Hash, HashOf, KeyPair};
    use iroha_data_model::{block::VersionedCommittedBlock, transaction::TransactionLimits};
    use once_cell::sync::Lazy;

    use super::*;
    use crate::{
        block::*, kura::Kura, smartcontracts::isi::Registrable as _, tx::TransactionValidator,
        wsv::World, PeersIds,
    };

    static ALICE_KEYS: Lazy<KeyPair> = Lazy::new(|| KeyPair::generate().unwrap());
    static ALICE_ID: Lazy<AccountId> =
        Lazy::new(|| AccountId::from_str("alice@wonderland").expect("Valid"));

    fn world_with_test_domains() -> World {
        let domain_id = DomainId::from_str("wonderland").expect("Valid");
        let mut domain = Domain::new(domain_id).build();
        let account = Account::new(ALICE_ID.clone(), [ALICE_KEYS.public_key().clone()]).build();
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
        let mut account = Account::new(ALICE_ID.clone(), [ALICE_KEYS.public_key().clone()]).build();
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

        let mut domain = Domain::new(DomainId::from_str("wonderland")?).build();
        let account = Account::new(ALICE_ID.clone(), [ALICE_KEYS.public_key().clone()])
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

    fn wsv_with_test_blocks_and_transactions(
        blocks: u64,
        valid_tx_per_block: usize,
        invalid_tx_per_block: usize,
    ) -> Result<WorldStateView> {
        let kura = Kura::blank_kura_for_testing();
        let wsv = WorldStateView::new(world_with_test_domains(), kura.clone());

        let limits = TransactionLimits {
            max_instruction_number: 1,
            max_wasm_size_bytes: 0,
        };
        let huge_limits = TransactionLimits {
            max_instruction_number: 1000,
            max_wasm_size_bytes: 0,
        };

        let valid_tx = {
            let tx =
                TransactionBuilder::new(ALICE_ID.clone(), vec![], 4000).sign(ALICE_KEYS.clone())?;
            VersionedAcceptedTransaction::from(AcceptedTransaction::accept::<false>(tx, &limits)?)
        };
        let invalid_tx = {
            let isi: InstructionBox = FailBox::new("fail").into();
            let tx = TransactionBuilder::new(ALICE_ID.clone(), vec![isi.clone(), isi], 4000)
                .sign(ALICE_KEYS.clone())?;
            AcceptedTransaction::accept::<false>(tx, &huge_limits)?.into()
        };

        let mut transactions = vec![valid_tx; valid_tx_per_block];
        transactions.append(&mut vec![invalid_tx; invalid_tx_per_block]);

        let first_block: VersionedCommittedBlock = PendingBlock::new(transactions.clone(), vec![])
            .chain_first()
            .validate(&TransactionValidator::new(limits), &wsv)
            .sign(ALICE_KEYS.clone())
            .expect("Failed to sign blocks.")
            .commit_unchecked()
            .into();

        let mut curr_hash = first_block.hash();

        wsv.apply(&first_block)?;
        kura.store_block(first_block);

        for height in 1u64..blocks {
            let block: VersionedCommittedBlock = PendingBlock::new(transactions.clone(), vec![])
                .chain(
                    height,
                    Some(curr_hash),
                    0,
                    crate::sumeragi::network_topology::Topology::new(vec![]),
                )
                .validate(&TransactionValidator::new(limits), &wsv)
                .sign(ALICE_KEYS.clone())
                .expect("Failed to sign blocks.")
                .commit_unchecked()
                .into();
            curr_hash = block.hash();
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
            bytes,
            Value::Vec(vec![1_u32.to_value(), 2_u32.to_value(), 3_u32.to_value()])
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
            bytes,
            Value::Vec(vec![1_u32.to_value(), 2_u32.to_value(), 3_u32.to_value()])
        );
        Ok(())
    }

    #[test]
    fn find_all_blocks() -> Result<()> {
        let num_blocks = 100;

        let wsv = wsv_with_test_blocks_and_transactions(num_blocks, 1, 1)?;

        let blocks = FindAllBlocks.execute(&wsv)?;

        assert_eq!(blocks.len() as u64, num_blocks);
        assert!(blocks.windows(2).all(|wnd| wnd[0] >= wnd[1]));

        Ok(())
    }

    #[test]
    fn find_all_block_headers() -> Result<()> {
        let num_blocks = 100;

        let wsv = wsv_with_test_blocks_and_transactions(num_blocks, 1, 1)?;

        let block_headers = FindAllBlockHeaders.execute(&wsv)?;

        assert_eq!(block_headers.len() as u64, num_blocks);
        assert!(block_headers.windows(2).all(|wnd| wnd[0] >= wnd[1]));

        Ok(())
    }

    #[test]
    fn find_block_header_by_hash() -> Result<()> {
        let wsv = wsv_with_test_blocks_and_transactions(1, 1, 1)?;

        let block = wsv
            .all_blocks_by_value()
            .into_iter()
            .last()
            .expect("WSV is empty");

        assert_eq!(
            &FindBlockHeaderByHash::new(*block.hash()).execute(&wsv)?,
            block.header()
        );

        assert!(FindBlockHeaderByHash::new(Hash::new([42]))
            .execute(&wsv)
            .is_err());

        Ok(())
    }

    #[test]
    fn find_all_transactions() -> Result<()> {
        let num_blocks = 100;

        let wsv = wsv_with_test_blocks_and_transactions(num_blocks, 1, 1)?;

        let txs = FindAllTransactions.execute(&wsv)?;

        assert_eq!(txs.len() as u64, num_blocks * 2);
        assert_eq!(
            txs.iter()
                .filter(|txn| matches!(txn.tx_value, TransactionValue::RejectedTransaction(_)))
                .count() as u64,
            num_blocks
        );
        assert_eq!(
            txs.iter()
                .filter(|txn| matches!(txn.tx_value, TransactionValue::Transaction(_)))
                .count() as u64,
            num_blocks
        );
        assert!(txs.windows(2).all(|wnd| wnd[0] >= wnd[1]));

        Ok(())
    }

    #[test]
    fn find_transaction() -> Result<()> {
        let kura = Kura::blank_kura_for_testing();
        let wsv = WorldStateView::new(world_with_test_domains(), kura.clone());

        let tx = TransactionBuilder::new(ALICE_ID.clone(), Vec::new(), 4000);
        let signed_tx = tx.sign(ALICE_KEYS.clone())?;

        let tx_limits = TransactionLimits {
            max_instruction_number: 4096,
            max_wasm_size_bytes: 0,
        };

        let va_tx: VersionedAcceptedTransaction =
            AcceptedTransaction::accept::<false>(signed_tx, &tx_limits)?.into();

        let mut block = PendingBlock::new(Vec::new(), Vec::new());
        block.transactions.push(va_tx.clone());
        let vcb = block
            .chain_first()
            .validate(&TransactionValidator::new(tx_limits), &wsv)
            .sign(ALICE_KEYS.clone())
            .expect("Failed to sign blocks.")
            .commit_unchecked()
            .into();
        wsv.apply(&vcb)?;
        kura.store_block(vcb);

        let wrong_hash: Hash = HashOf::new(&2_u8).into();
        let not_found = FindTransactionByHash::new(wrong_hash).execute(&wsv);
        assert!(matches!(not_found, Err(_)));

        let found_accepted = FindTransactionByHash::new(Hash::from(va_tx.hash())).execute(&wsv)?;
        match found_accepted {
            TransactionValue::Transaction(tx) => {
                assert_eq!(va_tx.hash().transmute(), tx.hash())
            }
            TransactionValue::RejectedTransaction(_) => {}
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
                .build();
            let account = Account::new(ALICE_ID.clone(), [ALICE_KEYS.public_key().clone()]).build();
            assert!(domain.add_account(account).is_none());
            let asset_definition_id = AssetDefinitionId::from_str("rose#wonderland")?;
            assert!(domain
                .add_asset_definition(
                    AssetDefinition::quantity(asset_definition_id).build(),
                    ALICE_ID.clone(),
                )
                .is_none());
            WorldStateView::new(World::with([domain], PeersIds::new()), kura)
        };

        let domain_id = DomainId::from_str("wonderland")?;
        let key = Name::from_str("Bytes")?;
        let bytes = FindDomainKeyValueByIdAndKey::new(domain_id, key).execute(&wsv)?;
        assert_eq!(
            bytes,
            Value::Vec(vec![1_u32.to_value(), 2_u32.to_value(), 3_u32.to_value()])
        );
        Ok(())
    }
}
