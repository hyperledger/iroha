//! Native application proof checkpoints must be pinned before any HTTP request.
use super::{
    evidence_http_tests::{base_url, capture_requests, client_with_base_url, empty_response},
    *,
};
use iroha_data_model::testing::native_finality::NativeFinalityFixture;

#[test]
fn proof_page_and_catch_up_reject_foreign_native_checkpoint_before_http() {
    let fixture = NativeFinalityFixture::start("sdk-independent-checkpoint");
    let checkpoint = fixture.checkpoint();
    let client = client_with_base_url(base_url());
    assert_ne!(client.network_id, checkpoint.network_id());
    let (errors, requests) = capture_requests(empty_response(StatusCode::OK), |transport| {
        let client = client.with_test_http_transport(transport);
        [
            client
                .get_validation_fee_current_policy_proof_page(&checkpoint)
                .unwrap_err(),
            client
                .catch_up_validation_fee_current_policy_proof(&checkpoint)
                .unwrap_err(),
        ]
    });
    for error in errors {
        assert!(error.to_string().contains("different network"), "{error:#}");
    }
    assert!(
        requests.is_empty(),
        "a foreign checkpoint cannot trigger HTTP"
    );
}
