//! Query functionality. The common error type is also defined here,
//! alongside functions for converting them into HTTP responses.
use std::cmp::Ordering;

use eyre::Result;
use iroha_data_model::{
    prelude::*,
    query::{
        error::QueryExecutionFail as Error, parameters::QueryParams, QueryBox, QueryOutputBatchBox,
        QueryRequest, QueryRequestWithAuthority, QueryResponse, SingularQueryBox,
        SingularQueryOutputBox,
    },
};

use crate::{
    prelude::ValidSingularQuery,
    query::{
        cursor::QueryBatchedErasedIterator, pagination::Paginate as _, store::LiveQueryStoreHandle,
    },
    smartcontracts::{wasm, ValidQuery},
    state::{StateReadOnly, WorldReadOnly},
};

/// Allows to generalize retrieving the metadata key for all the query output types
pub trait SortableQueryOutput {
    /// Get the sorting key for the output, from metadata
    ///
    /// If the type doesn't have metadata or metadata key doesn't exist - return None
    fn get_metadata_sorting_key(&self, key: &Name) -> Option<JsonString>;
}

impl SortableQueryOutput for Account {
    fn get_metadata_sorting_key(&self, key: &Name) -> Option<JsonString> {
        self.metadata.get(key).cloned()
    }
}

impl SortableQueryOutput for Domain {
    fn get_metadata_sorting_key(&self, key: &Name) -> Option<JsonString> {
        self.metadata.get(key).cloned()
    }
}

impl SortableQueryOutput for AssetDefinition {
    fn get_metadata_sorting_key(&self, key: &Name) -> Option<JsonString> {
        self.metadata.get(key).cloned()
    }
}

impl SortableQueryOutput for Asset {
    fn get_metadata_sorting_key(&self, key: &Name) -> Option<JsonString> {
        match &self.value {
            AssetValue::Numeric(_) => None,
            AssetValue::Store(metadata) => metadata.get(key).cloned(),
        }
    }
}

impl SortableQueryOutput for Role {
    fn get_metadata_sorting_key(&self, _key: &Name) -> Option<JsonString> {
        None
    }
}

impl SortableQueryOutput for RoleId {
    fn get_metadata_sorting_key(&self, _key: &Name) -> Option<JsonString> {
        None
    }
}

impl SortableQueryOutput for TransactionQueryOutput {
    fn get_metadata_sorting_key(&self, _key: &Name) -> Option<JsonString> {
        None
    }
}

impl SortableQueryOutput for Peer {
    fn get_metadata_sorting_key(&self, _key: &Name) -> Option<JsonString> {
        None
    }
}

impl SortableQueryOutput for Permission {
    fn get_metadata_sorting_key(&self, _key: &Name) -> Option<JsonString> {
        None
    }
}

impl SortableQueryOutput for Trigger {
    fn get_metadata_sorting_key(&self, _key: &Name) -> Option<JsonString> {
        None
    }
}

impl SortableQueryOutput for TriggerId {
    fn get_metadata_sorting_key(&self, _key: &Name) -> Option<JsonString> {
        None
    }
}

impl SortableQueryOutput for iroha_data_model::block::SignedBlock {
    fn get_metadata_sorting_key(&self, _key: &Name) -> Option<JsonString> {
        None
    }
}

impl SortableQueryOutput for iroha_data_model::block::BlockHeader {
    fn get_metadata_sorting_key(&self, _key: &Name) -> Option<JsonString> {
        None
    }
}

/// Applies sorting and pagination to the query output and wraps it into a type-erasing batching iterator.
///
/// # Errors
///
/// Returns an error if the fetch size is too big
pub fn apply_query_postprocessing<I>(
    iter: I,
    &QueryParams {
        pagination,
        ref sorting,
        fetch_size,
    }: &QueryParams,
) -> Result<QueryBatchedErasedIterator, Error>
where
    I: Iterator,
    I::Item: SortableQueryOutput + Send + Sync + 'static,
    QueryOutputBatchBox: From<Vec<I::Item>>,
{
    // validate the fetch (aka batch) size
    let fetch_size = fetch_size
        .fetch_size
        .unwrap_or(iroha_data_model::query::parameters::DEFAULT_FETCH_SIZE);
    if fetch_size > iroha_data_model::query::parameters::MAX_FETCH_SIZE {
        return Err(Error::FetchSizeTooBig);
    }

    // sort & paginate, erase the iterator with QueryBatchedErasedIterator
    let output = match &sorting.sort_by_metadata_key {
        Some(key) => {
            // if sorting was requested, we need to retrieve all the results first
            let mut pairs: Vec<(Option<JsonString>, I::Item)> = iter
                .map(|value| {
                    let key = value.get_metadata_sorting_key(key);
                    (key, value)
                })
                .collect();
            pairs.sort_by(
                |(left_key, _), (right_key, _)| match (left_key, right_key) {
                    (Some(l), Some(r)) => l.cmp(r),
                    (Some(_), None) => Ordering::Less,
                    (None, Some(_)) => Ordering::Greater,
                    (None, None) => Ordering::Equal,
                },
            );

            QueryBatchedErasedIterator::new(
                pairs.into_iter().map(|(_, val)| val).paginate(pagination),
                fetch_size,
            )
        }
        // no sorting required, can just paginate the results without constructing the full output vec
        None => {
            // FP: this collect is very deliberate
            #[allow(clippy::needless_collect)]
            let output = iter
                .paginate(pagination)
                // it should theoretically be possible to not collect the results into a vec and build the response lazily
                // but:
                // - the iterator is bound to the 'state lifetime and this lifetime should somehow be erased
                // - for small queries this might not be efficient
                // TODO: investigate this
                .collect::<Vec<_>>();

            QueryBatchedErasedIterator::new(output.into_iter(), fetch_size)
        }
    };

    Ok(output)
}

/// Query Request statefully validated on the Iroha node side.
#[derive(Debug, Clone)]
pub struct ValidQueryRequest(QueryRequest);

impl ValidQueryRequest {
    /// Validate a query for an API client by calling the executor.
    ///
    /// # Errors
    ///
    /// Returns an error if the query validation fails.
    pub fn validate_for_client(
        query: QueryRequestWithAuthority,
        state_ro: &impl StateReadOnly,
    ) -> Result<Self, ValidationFail> {
        state_ro
            .world()
            .executor()
            .validate_query(state_ro, &query.authority, &query.request)?;
        Ok(Self(query.request))
    }

    /// Validate a query for a wasm program.
    ///
    /// The validation logic is defined by the implementation of the [`ValidateQueryOperation`] trait.
    ///
    /// # Errors
    ///
    /// Returns an error if the query validation fails.
    pub fn validate_for_wasm<W, S>(
        query: QueryRequest,
        state: &mut wasm::state::CommonState<W, S>,
    ) -> Result<Self, ValidationFail>
    where
        wasm::state::CommonState<W, S>: wasm::state::ValidateQueryOperation,
    {
        use wasm::state::ValidateQueryOperation as _;

        state.validate_query(state.authority(), &query)?;

        Ok(Self(query))
    }

    /// Execute a validated query request
    ///
    /// # Errors
    ///
    /// Returns an error if the query execution fails.
    #[allow(clippy::too_many_lines)] // not much we can do, we _need_ to list all the box types here
    pub fn execute(
        self,
        live_query_store: &LiveQueryStoreHandle,
        state: &impl StateReadOnly,
        authority: &AccountId,
    ) -> Result<QueryResponse, Error> {
        match self.0 {
            QueryRequest::Singular(singular_query) => {
                let output = match singular_query {
                    SingularQueryBox::FindAssetQuantityById(q) => {
                        SingularQueryOutputBox::from(q.execute(state)?)
                    }
                    SingularQueryBox::FindExecutorDataModel(q) => {
                        SingularQueryOutputBox::from(q.execute(state)?)
                    }
                    SingularQueryBox::FindParameters(q) => {
                        SingularQueryOutputBox::from(q.execute(state)?)
                    }
                    SingularQueryBox::FindTotalAssetQuantityByAssetDefinitionId(q) => {
                        SingularQueryOutputBox::from(q.execute(state)?)
                    }
                    SingularQueryBox::FindTriggerById(q) => {
                        SingularQueryOutputBox::from(q.execute(state)?)
                    }
                    SingularQueryBox::FindDomainMetadata(q) => {
                        SingularQueryOutputBox::from(q.execute(state)?)
                    }
                    SingularQueryBox::FindAccountMetadata(q) => {
                        SingularQueryOutputBox::from(q.execute(state)?)
                    }
                    SingularQueryBox::FindAssetMetadata(q) => {
                        SingularQueryOutputBox::from(q.execute(state)?)
                    }
                    SingularQueryBox::FindAssetDefinitionMetadata(q) => {
                        SingularQueryOutputBox::from(q.execute(state)?)
                    }
                    SingularQueryBox::FindTriggerMetadata(q) => {
                        SingularQueryOutputBox::from(q.execute(state)?)
                    }
                    SingularQueryBox::FindTransactionByHash(q) => {
                        SingularQueryOutputBox::from(q.execute(state)?)
                    }
                    SingularQueryBox::FindBlockHeaderByHash(q) => {
                        SingularQueryOutputBox::from(q.execute(state)?)
                    }
                };

                Ok(QueryResponse::Singular(output))
            }
            QueryRequest::Start(iter_query) => {
                let output = match iter_query.query {
                    // dispatch on a concrete query type, erasing the type with `QueryBatchedErasedIterator` in the end
                    QueryBox::FindDomains(q) => apply_query_postprocessing(
                        ValidQuery::execute(q.query, q.predicate, state)?,
                        &iter_query.params,
                    )?,
                    QueryBox::FindAccounts(q) => apply_query_postprocessing(
                        ValidQuery::execute(q.query, q.predicate, state)?,
                        &iter_query.params,
                    )?,
                    QueryBox::FindAssets(q) => apply_query_postprocessing(
                        ValidQuery::execute(q.query, q.predicate, state)?,
                        &iter_query.params,
                    )?,
                    QueryBox::FindAssetsDefinitions(q) => apply_query_postprocessing(
                        ValidQuery::execute(q.query, q.predicate, state)?,
                        &iter_query.params,
                    )?,
                    QueryBox::FindRoles(q) => apply_query_postprocessing(
                        ValidQuery::execute(q.query, q.predicate, state)?,
                        &iter_query.params,
                    )?,
                    QueryBox::FindRoleIds(q) => apply_query_postprocessing(
                        ValidQuery::execute(q.query, q.predicate, state)?,
                        &iter_query.params,
                    )?,
                    QueryBox::FindPermissionsByAccountId(q) => apply_query_postprocessing(
                        ValidQuery::execute(q.query, q.predicate, state)?,
                        &iter_query.params,
                    )?,
                    QueryBox::FindRolesByAccountId(q) => apply_query_postprocessing(
                        ValidQuery::execute(q.query, q.predicate, state)?,
                        &iter_query.params,
                    )?,
                    QueryBox::FindTransactionsByAccountId(q) => apply_query_postprocessing(
                        ValidQuery::execute(q.query, q.predicate, state)?,
                        &iter_query.params,
                    )?,
                    QueryBox::FindAccountsWithAsset(q) => apply_query_postprocessing(
                        ValidQuery::execute(q.query, q.predicate, state)?,
                        &iter_query.params,
                    )?,
                    QueryBox::FindPeers(q) => apply_query_postprocessing(
                        ValidQuery::execute(q.query, q.predicate, state)?,
                        &iter_query.params,
                    )?,
                    QueryBox::FindActiveTriggerIds(q) => apply_query_postprocessing(
                        ValidQuery::execute(q.query, q.predicate, state)?,
                        &iter_query.params,
                    )?,
                    QueryBox::FindTransactions(q) => apply_query_postprocessing(
                        ValidQuery::execute(q.query, q.predicate, state)?,
                        &iter_query.params,
                    )?,
                    QueryBox::FindBlocks(q) => apply_query_postprocessing(
                        ValidQuery::execute(q.query, q.predicate, state)?,
                        &iter_query.params,
                    )?,
                    QueryBox::FindBlockHeaders(q) => apply_query_postprocessing(
                        ValidQuery::execute(q.query, q.predicate, state)?,
                        &iter_query.params,
                    )?,
                };

                Ok(QueryResponse::Iterable(
                    live_query_store.handle_iter_start(output, authority)?,
                ))
            }
            QueryRequest::Continue(cursor) => Ok(QueryResponse::Iterable(
                live_query_store.handle_iter_continue(cursor)?,
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use iroha_crypto::{Hash, HashOf, KeyPair};
    use iroha_data_model::{
        parameter::TransactionParameters,
        query::{error::FindError, predicate::CompoundPredicate},
    };
    use iroha_primitives::json::JsonString;
    use nonzero_ext::nonzero;
    use test_samples::{gen_account_in, ALICE_ID, ALICE_KEYPAIR};
    use tokio::test;

    use super::*;
    use crate::{
        block::*,
        kura::Kura,
        query::store::LiveQueryStore,
        smartcontracts::isi::Registrable as _,
        state::{State, World},
        sumeragi::network_topology::Topology,
        tx::AcceptedTransaction,
    };

    fn world_with_test_domains() -> World {
        let domain_id = DomainId::from_str("wonderland").expect("Valid");
        let domain = Domain::new(domain_id).build(&ALICE_ID);
        let account = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
        let asset_definition_id = AssetDefinitionId::from_str("rose#wonderland").expect("Valid");
        let asset_definition = AssetDefinition::numeric(asset_definition_id).build(&ALICE_ID);
        World::with([domain], [account], [asset_definition])
    }

    fn world_with_test_asset_with_metadata() -> World {
        let asset_definition_id = AssetDefinitionId::from_str("rose#wonderland").expect("Valid");
        let domain = Domain::new(DomainId::from_str("wonderland").expect("Valid")).build(&ALICE_ID);
        let account = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
        let asset_definition =
            AssetDefinition::numeric(asset_definition_id.clone()).build(&ALICE_ID);

        let mut store = Metadata::default();
        store.insert(
            Name::from_str("Bytes").expect("Valid"),
            vec![1_u32, 2_u32, 3_u32],
        );
        let asset_id = AssetId::new(asset_definition_id, account.id().clone());
        let asset = Asset::new(asset_id, AssetValue::Store(store));

        World::with_assets([domain], [account], [asset_definition], [asset])
    }

    fn world_with_test_account_with_metadata() -> Result<World> {
        let mut metadata = Metadata::default();
        metadata.insert(Name::from_str("Bytes")?, vec![1_u32, 2_u32, 3_u32]);

        let domain = Domain::new(DomainId::from_str("wonderland")?).build(&ALICE_ID);
        let account = Account::new(ALICE_ID.clone())
            .with_metadata(metadata)
            .build(&ALICE_ID);
        let asset_definition_id = AssetDefinitionId::from_str("rose#wonderland").expect("Valid");
        let asset_definition = AssetDefinition::numeric(asset_definition_id).build(&ALICE_ID);
        Ok(World::with([domain], [account], [asset_definition]))
    }

    fn state_with_test_blocks_and_transactions(
        blocks: u64,
        valid_tx_per_block: usize,
        invalid_tx_per_block: usize,
    ) -> Result<State> {
        let chain_id = ChainId::from("00000000-0000-0000-0000-000000000000");

        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::test().start();
        let state = State::new(world_with_test_domains(), kura.clone(), query_handle);
        {
            let mut state_block = state.block();
            let limits = TransactionParameters {
                max_instructions: nonzero!(1000_u64),
                smart_contract_size: nonzero!(1024_u64),
            };
            let huge_limits = TransactionParameters {
                max_instructions: nonzero!(1000_u64),
                smart_contract_size: nonzero!(1024_u64),
            };

            state_block.world.parameters.transaction = limits;

            let valid_tx = {
                let tx = TransactionBuilder::new(chain_id.clone(), ALICE_ID.clone())
                    .with_instructions::<InstructionBox>([])
                    .sign(ALICE_KEYPAIR.private_key());
                AcceptedTransaction::accept(tx, &chain_id, limits)?
            };
            let invalid_tx = {
                let fail_isi = Unregister::domain("dummy".parse().unwrap());
                let tx = TransactionBuilder::new(chain_id.clone(), ALICE_ID.clone())
                    .with_instructions([fail_isi.clone(), fail_isi])
                    .sign(ALICE_KEYPAIR.private_key());
                AcceptedTransaction::accept(tx, &chain_id, huge_limits)?
            };

            let mut transactions = vec![valid_tx; valid_tx_per_block];
            transactions.append(&mut vec![invalid_tx; invalid_tx_per_block]);

            let (peer_public_key, peer_private_key) = KeyPair::random().into_parts();
            let peer_id = PeerId::new("127.0.0.1:8080".parse().unwrap(), peer_public_key);
            let topology = Topology::new(vec![peer_id]);
            let first_block = BlockBuilder::new(transactions.clone())
                .chain(0, &mut state_block)
                .sign(&peer_private_key)
                .unpack(|_| {})
                .commit(&topology)
                .unpack(|_| {})
                .expect("Block is valid");

            let _events = state_block.apply(&first_block, topology.as_ref().to_owned())?;
            kura.store_block(first_block);

            for _ in 1u64..blocks {
                let block = BlockBuilder::new(transactions.clone())
                    .chain(0, &mut state_block)
                    .sign(&peer_private_key)
                    .unpack(|_| {})
                    .commit(&topology)
                    .unpack(|_| {})
                    .expect("Block is valid");

                let _events = state_block.apply(&block, topology.as_ref().to_owned())?;
                kura.store_block(block);
            }
            state_block.commit();
        }

        Ok(state)
    }

    #[test]
    async fn asset_store() -> Result<()> {
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::test().start();
        let state = State::new(world_with_test_asset_with_metadata(), kura, query_handle);

        let asset_definition_id = AssetDefinitionId::from_str("rose#wonderland")?;
        let asset_id = AssetId::new(asset_definition_id, ALICE_ID.clone());
        let bytes =
            FindAssetMetadata::new(asset_id, Name::from_str("Bytes")?).execute(&state.view())?;
        assert_eq!(JsonString::from(vec![1_u32, 2_u32, 3_u32,]), bytes,);
        Ok(())
    }

    #[test]
    async fn account_metadata() -> Result<()> {
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::test().start();
        let state = State::new(world_with_test_account_with_metadata()?, kura, query_handle);

        let bytes = FindAccountMetadata::new(ALICE_ID.clone(), Name::from_str("Bytes")?)
            .execute(&state.view())?;
        assert_eq!(JsonString::from(vec![1_u32, 2_u32, 3_u32,]), bytes,);
        Ok(())
    }

    #[test]
    async fn find_all_blocks() -> Result<()> {
        let num_blocks = 100;

        let state = state_with_test_blocks_and_transactions(num_blocks, 1, 1)?;
        let blocks = ValidQuery::execute(FindBlocks, CompoundPredicate::PASS, &state.view())?
            .collect::<Vec<_>>();

        assert_eq!(blocks.len() as u64, num_blocks);
        assert!(blocks
            .windows(2)
            .all(|wnd| wnd[0].header() >= wnd[1].header()));

        Ok(())
    }

    #[test]
    async fn find_all_block_headers() -> Result<()> {
        let num_blocks = 100;

        let state = state_with_test_blocks_and_transactions(num_blocks, 1, 1)?;
        let block_headers =
            ValidQuery::execute(FindBlockHeaders, CompoundPredicate::PASS, &state.view())?
                .collect::<Vec<_>>();

        assert_eq!(block_headers.len() as u64, num_blocks);
        assert!(block_headers.windows(2).all(|wnd| wnd[0] >= wnd[1]));

        Ok(())
    }

    #[test]
    async fn find_block_header_by_hash() -> Result<()> {
        let state = state_with_test_blocks_and_transactions(1, 1, 1)?;
        let state_view = state.view();
        let block = state_view.all_blocks().last().expect("state is empty");

        assert_eq!(
            FindBlockHeaderByHash::new(block.hash()).execute(&state_view)?,
            *block.header()
        );

        assert!(
            FindBlockHeaderByHash::new(HashOf::from_untyped_unchecked(Hash::new([42])))
                .execute(&state_view)
                .is_err()
        );

        Ok(())
    }

    #[test]
    async fn find_all_transactions() -> Result<()> {
        let num_blocks = 100;

        let state = state_with_test_blocks_and_transactions(num_blocks, 1, 1)?;
        let txs = ValidQuery::execute(FindTransactions, CompoundPredicate::PASS, &state.view())?
            .collect::<Vec<_>>();

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
    async fn find_transaction() -> Result<()> {
        let chain_id = ChainId::from("00000000-0000-0000-0000-000000000000");

        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::test().start();
        let state = State::new(world_with_test_domains(), kura.clone(), query_handle);

        let mut state_block = state.block();
        let tx = TransactionBuilder::new(chain_id.clone(), ALICE_ID.clone())
            .with_instructions::<InstructionBox>([])
            .sign(ALICE_KEYPAIR.private_key());

        let tx_limits = state_block.transaction_executor().limits;
        let va_tx = AcceptedTransaction::accept(tx, &chain_id, tx_limits)?;

        let (peer_public_key, _) = KeyPair::random().into_parts();
        let peer_id = PeerId::new("127.0.0.1:8080".parse().unwrap(), peer_public_key);
        let topology = Topology::new(vec![peer_id]);
        let vcb = BlockBuilder::new(vec![va_tx.clone()])
            .chain(0, &mut state_block)
            .sign(ALICE_KEYPAIR.private_key())
            .unpack(|_| {})
            .commit(&topology)
            .unpack(|_| {})
            .expect("Block is valid");

        let _events = state_block.apply(&vcb, topology.as_ref().to_owned())?;
        kura.store_block(vcb);
        state_block.commit();

        let state_view = state.view();

        let unapplied_tx = TransactionBuilder::new(chain_id, ALICE_ID.clone())
            .with_instructions([Unregister::account(gen_account_in("domain").0)])
            .sign(ALICE_KEYPAIR.private_key());
        let wrong_hash = unapplied_tx.hash();
        let not_found = FindTransactionByHash::new(wrong_hash).execute(&state_view);
        assert!(matches!(
            not_found,
            Err(Error::Find(FindError::Transaction(_)))
        ));

        let found_accepted =
            FindTransactionByHash::new(va_tx.as_ref().hash()).execute(&state_view)?;
        if found_accepted.transaction.error.is_none() {
            assert_eq!(
                va_tx.as_ref().hash(),
                found_accepted.as_ref().as_ref().hash()
            )
        }
        Ok(())
    }

    #[test]
    async fn domain_metadata() -> Result<()> {
        let kura = Kura::blank_kura_for_testing();
        let state = {
            let mut metadata = Metadata::default();
            metadata.insert(Name::from_str("Bytes")?, vec![1_u32, 2_u32, 3_u32]);
            let domain = Domain::new(DomainId::from_str("wonderland")?)
                .with_metadata(metadata)
                .build(&ALICE_ID);
            let account = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
            let asset_definition_id = AssetDefinitionId::from_str("rose#wonderland")?;
            let asset_definition = AssetDefinition::numeric(asset_definition_id).build(&ALICE_ID);
            let query_handle = LiveQueryStore::test().start();
            State::new(
                World::with([domain], [account], [asset_definition]),
                kura,
                query_handle,
            )
        };

        let domain_id = DomainId::from_str("wonderland")?;
        let key = Name::from_str("Bytes")?;
        let bytes = FindDomainMetadata::new(domain_id, key).execute(&state.view())?;
        assert_eq!(JsonString::from(vec![1_u32, 2_u32, 3_u32,]), bytes,);
        Ok(())
    }
}
