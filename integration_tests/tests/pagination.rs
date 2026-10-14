//! Pagination behaviour integration tests for query iterators.
use eyre::Result;
use integration_tests::sandbox;
use iroha::{
    blocking::Client,
    data_model::{asset::AssetDefinition, isi::InstructionBox, prelude::*},
};
use iroha_data_model::query::dsl::SelectorTuple;
use iroha_model_base::domain::DomainId;
use iroha_model_base::name::Name;
use iroha_test_network::*;
use nonzero_ext::nonzero;
#[test]
fn pagination_behaves() -> Result<()> {
    // Stored cursors are required to validate multi-batch pagination behavior.
    let Some((network, _rt)) = sandbox::start_network_blocking_or_skip(
        NetworkBuilder::new()
            .with_block_cadence(std::time::Duration::from_secs(2))
            .with_config_layer(|layer| {
                layer.write(["pipeline", "query_default_cursor_mode"], "stored");
            }),
        stringify!(pagination_behaves),
    )?
    else {
        return Ok(());
    };
    let client = network.client();
    register_assets(&client)?;
    // limits_should_work
    let vec = client
        .client()
        .query(FindAssetDefinitions::new())
        .with_pagination(Pagination::new(Some(nonzero!(7_u64)), 0))
        .execute_all()?;
    assert_eq!(vec.len(), 7);
    // Stored bounded cursors intentionally omit exact remaining counts so the
    // first response can stay cheap; the iterator reports the current batch as
    // the lower bound and streams the rest through cursors.
    let mut iter = client
        .client()
        .query(FindAssetDefinitions::new())
        .with_pagination(Pagination::new(Some(nonzero!(7_u64)), 0))
        .with_fetch_size(FetchSize::new(Some(nonzero!(3_u64))))
        .execute()?;
    assert_eq!(iter.size_hint(), (3, None));
    for _ in 0..4 {
        iter.next().unwrap().unwrap();
    }
    assert_eq!(iter.size_hint(), (2, None));
    let remaining = iter.collect::<Result<Vec<_>, _>>()?;
    assert_eq!(remaining.len(), 3);
    // fetch_size_should_work
    {
        use iroha::data_model::query::{
            QueryBox, QueryOutputBatchBox, QueryWithFilter, QueryWithParams,
            builder::QueryExecutor as _,
            dsl::CompoundPredicate,
            parameters::{FetchSize, QueryParams, Sorting},
        };
        let with_filter: QueryWithFilter<AssetDefinition> =
            QueryWithFilter::new_with_query((), CompoundPredicate::PASS, SelectorTuple::default());
        let qbox: QueryBox<QueryOutputBatchBox> = with_filter.into();
        let query = QueryWithParams::new(
            &qbox,
            QueryParams::new(
                Pagination::new(Some(nonzero!(7_u64)), 0),
                Sorting::default(),
                FetchSize::new(Some(nonzero!(3_u64))),
            ),
        )
        .expect("asset-definition query type has a canonical mapping");
        let (first_batch, remaining_items, _continue_cursor) =
            client.client().start_query(query)?;
        assert_eq!(first_batch.len(), 3);
        assert_eq!(remaining_items, None);
    }
    Ok(())
}
fn register_assets(client: &Client) -> Result<()> {
    const MAX_INSTRUCTIONS_PER_TX: usize = 5;
    let register: Vec<InstructionBox> = pagination_asset_definitions()
        .into_iter()
        .map(|(asset_definition_id, name)| {
            Register::asset_definition({
                let __asset_definition_id = asset_definition_id;
                AssetDefinition::numeric(
                    __asset_definition_id.clone(),
                    name,
                    iroha_data_model::asset::AssetBalancePolicy::Global,
                    None,
                )
            })
            .into()
        })
        .collect();
    for chunk in register.chunks(MAX_INSTRUCTIONS_PER_TX) {
        client.submit_all::<InstructionBox>(
            chunk.iter().cloned(),
            iroha::data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )?;
    }
    Ok(())
}
fn pagination_asset_definitions() -> Vec<(AssetDefinitionId, String)> {
    ('a'..='j')
        .map(|c| c.to_string())
        .map(|name| {
            let id = AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").expect("wonderland domain is valid"),
                name.parse::<Name>().expect("single-letter name is valid"),
            );
            (id, name)
        })
        .collect()
}
#[test]
fn pagination_asset_definition_ids_are_canonical_base58_literals() {
    let definitions = pagination_asset_definitions();
    assert_eq!(definitions.len(), 10);
    for (id, _) in definitions {
        let literal = id.to_string();
        assert!(!literal.contains(':'));
        assert_eq!(literal.parse::<AssetDefinitionId>().expect("canonical"), id);
    }
}
