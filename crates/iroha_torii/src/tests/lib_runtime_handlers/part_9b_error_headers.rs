#[test]
fn accept_transaction_limit_failure_sets_header_code() {
    let err =
        super::Error::AcceptTransaction(iroha_core::tx::AcceptTransactionFail::TransactionLimit(
            iroha_data_model::transaction::error::TransactionLimitError {
                reason: "too big".into(),
            },
        ));
    let response = err.into_response();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let headers = response.headers();
    assert_eq!(
        headers
            .get("x-iroha-reject-code")
            .and_then(|v| v.to_str().ok()),
        Some("transaction_rejected")
    );
    let body = executor::block_on(http_body_util::BodyExt::collect(response.into_body()))
        .expect("collect body")
        .to_bytes();
    let envelope =
        norito::decode_from_bytes::<super::ErrorEnvelope>(&body).expect("decode error envelope");
    assert_eq!(envelope.code(), "transaction_rejected");
    assert!(envelope.message().contains("too big"));
}
#[test]
fn accept_transaction_nts_unhealthy_sets_header_code() {
    let err = super::Error::AcceptTransaction(
        iroha_core::tx::AcceptTransactionFail::NetworkTimeUnhealthy {
            reason: "fallback".to_owned(),
        },
    );
    let response = err.into_response();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let headers = response.headers();
    assert_eq!(
        headers
            .get("x-iroha-reject-code")
            .and_then(|v| v.to_str().ok()),
        Some("PRTRY:NTS_UNHEALTHY")
    );
    let body = executor::block_on(http_body_util::BodyExt::collect(response.into_body()))
        .expect("collect body")
        .to_bytes();
    let envelope =
        norito::decode_from_bytes::<super::ErrorEnvelope>(&body).expect("decode error envelope");
    assert_eq!(envelope.code(), "PRTRY:NTS_UNHEALTHY");
    assert!(
        envelope
            .message()
            .contains("Network time service is unhealthy")
    );
}
#[test]
fn query_conversion_error_does_not_infer_a_reject_code_header() {
    use iroha_data_model::query::error::QueryExecutionFail;
    let err = super::Error::Query(iroha_data_model::ValidationFail::QueryFailed(
        QueryExecutionFail::Conversion("invalid_proof:recursive proof is invalid".to_owned()),
    ));
    let response = err.into_response();
    assert!(
        response.headers().get("x-iroha-reject-code").is_none(),
        "conversion messages never carry a protocol-specific reject code"
    );
}

#[test]
fn anonymous_ballot_unavailable_is_not_a_transaction_rejection() {
    let error = super::Error::AcceptTransaction(
        iroha_core::tx::AcceptTransactionFail::AnonymousBallotUnavailable,
    );
    assert_eq!(error.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    let response = error.into_response();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(response.headers().get("x-iroha-reject-code").is_none());
    let body = executor::block_on(http_body_util::BodyExt::collect(response.into_body()))
        .expect("collect body")
        .to_bytes();
    let envelope = norito::decode_from_bytes::<super::ErrorEnvelope>(&body).unwrap();
    assert_eq!(envelope.code(), "anonymous_ballot_unavailable");
    assert!(
        envelope
            .details
            .as_ref()
            .is_none_or(|details| details.reject_code.is_none())
    );
}

#[test]
fn anonymous_ballot_pipeline_rejection_labels_are_exact_committed_outcomes() {
    use iroha_data_model::{
        governance::anonymous_ballot::AnonymousBallotRejectionV1,
        transaction::error::TransactionRejectionReason,
    };
    for (reason, summary) in [
        (
            AnonymousBallotRejectionV1::OutsideCastingWindow,
            "Anonymous ballot is outside its casting window.",
        ),
        (
            AnonymousBallotRejectionV1::DuplicateNullifier,
            "Anonymous ballot nullifier was already accepted.",
        ),
    ] {
        let reason = TransactionRejectionReason::AnonymousBallot(reason);
        assert_eq!(
            super::transaction_rejection_code(&reason),
            "anonymous_ballot"
        );
        assert_eq!(super::pipeline_rejection_summary(&reason), summary);
    }
}
