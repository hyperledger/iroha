use nonzero_ext::nonzero;

#[tokio::test]
async fn ledger_headers_reports_missing_canonical_body() {
    let app = mk_app_state_for_tests();
    let (block, _) = make_signed_block(1, None);
    let block_hash = block.hash();
    record_committed_block_hash_for_test(&app, block.header(), block_hash);

    let error = super::handler_ledger_headers(
        State(app),
        crate::NoritoQuery(routing::HistoryWindowQuery {
            from: Some(1),
            limit: Some(1),
        }),
        HeaderMap::new(),
    )
    .await
    .expect_err("a committed hash without its body must fail");
    assert!(matches!(
        error,
        Error::Query(ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::CanonicalHistory(
                iroha_data_model::query::error::CanonicalHistoryError::BodyUnavailable {
                    height: 1,
                    ..
                }
            )
        ))
    ));
}

#[tokio::test]
async fn ledger_headers_reports_authenticated_hash_only_gap() {
    let app = mk_app_state_for_tests();
    let (block, _) = make_signed_block(1, None);
    let header = block.header();
    let block_hash = store_block(&app, block);
    record_committed_block_hash_for_test(&app, header, block_hash);
    app.kura
        .corrupt_canonical_body_for_testing(nonzero!(1_usize))
        .expect("convert Torii history fixture to authenticated hash-only form");

    let error = super::handler_ledger_headers(
        State(app),
        crate::NoritoQuery(routing::HistoryWindowQuery {
            from: Some(1),
            limit: Some(1),
        }),
        HeaderMap::new(),
    )
    .await
    .expect_err("hash-only history must be an explicit availability failure");
    assert!(matches!(
        error,
        Error::Query(ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::CanonicalHistory(
                iroha_data_model::query::error::CanonicalHistoryError::BodyUnavailable {
                    height: 1,
                    ..
                }
            )
        ))
    ));
}

#[test]
fn canonical_history_http_status_distinguishes_unavailable_from_corrupt() {
    use iroha_data_model::query::error::{CanonicalHistoryError, QueryExecutionFail};

    let unavailable = ValidationFail::QueryFailed(QueryExecutionFail::CanonicalHistory(
        CanonicalHistoryError::HeightOutsideSnapshot {
            height: 2,
            committed_height: 1,
        },
    ));
    let corrupt = ValidationFail::QueryFailed(QueryExecutionFail::CanonicalHistory(
        CanonicalHistoryError::BlockHeightMismatch {
            height: 1,
            actual_height: 2,
        },
    ));
    assert_eq!(
        Error::query_status_code(&unavailable),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        Error::query_status_code(&corrupt),
        StatusCode::INTERNAL_SERVER_ERROR
    );
}

include!("pipeline_status_bounded_outcome.rs");
