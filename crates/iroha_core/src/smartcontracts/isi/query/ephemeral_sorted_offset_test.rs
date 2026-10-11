// Pagination regression tests for ephemeral sorted queries.
#[tokio::test]
async fn ephemeral_sorted_query_respects_offset_and_limit() {
    use iroha_data_model::{
        domain::Domain,
        query::parameters::{FetchSize, Pagination, QueryParams, Sorting},
    };
    use nonzero_ext::nonzero;
    let mut d1 = Domain::new(DomainId::try_new("d1", "universal").unwrap()).build(&ALICE_ID);
    let mut d2 = Domain::new(DomainId::try_new("d2", "universal").unwrap()).build(&ALICE_ID);
    let mut d3 = Domain::new(DomainId::try_new("d3", "universal").unwrap()).build(&ALICE_ID);
    let d4 = Domain::new(DomainId::try_new("d4", "universal").unwrap()).build(&ALICE_ID);
    d1.metadata_mut()
        .insert("rank".parse().unwrap(), Json::from(norito::json!(1)));
    d2.metadata_mut()
        .insert("rank".parse().unwrap(), Json::from(norito::json!(2)));
    d3.metadata_mut()
        .insert("rank".parse().unwrap(), Json::from(norito::json!(3)));
    let params = QueryParams {
        pagination: Pagination {
            offset: 1,
            limit: Some(nonzero!(2_u64)),
        },
        sorting: Sorting::by_metadata_key("rank".parse().unwrap()),
        fetch_size: FetchSize {
            fetch_size: Some(nonzero!(2_u64)),
        },
    };
    let selector = SelectorTuple::<Domain>::default();
    let (output, stats) = apply_query_postprocessing_ephemeral_with_budget(
        vec![d4, d3.clone(), d1, d2.clone()].into_iter(),
        selector,
        &params,
        QueryLimits::default(),
        None,
    )
    .expect("postprocess");
    assert_eq!(stats.processed_items(), 4);
    let (batch, remaining, cursor) = output.into_parts();
    assert!(cursor.is_none());
    assert_eq!(remaining, 0);
    let mut tuple_iter = batch.into_iter();
    let v = match tuple_iter.next().expect("slice") {
        iroha_data_model::query::QueryOutputBatchBox::Domain(v) => v,
        other => panic!("unexpected batch variant: {other:?}"),
    };
    assert_eq!(v.len(), 2);
    assert_eq!(v[0].id, d2.id);
    assert_eq!(v[1].id, d3.id);
}
