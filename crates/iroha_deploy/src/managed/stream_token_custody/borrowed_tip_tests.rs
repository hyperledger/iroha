//! Genuine certified custody reads preserve deadline refusal and original transport retry.

use super::renewal_tests::Fixture;
use super::*;
use crate::managed::native_operation::test_support::UnavailablePeers;

#[test]
fn native_current_read_keeps_expired_deadline_before_transport_and_original_retry() {
    let _guard = crate::managed::native_test_guard();
    let fixture = Fixture::enrolled(4_000);
    let verifier = fixture.native.observe(&fixture.owner.authority);
    let original = verifier.checkpoint().encode_canonical().unwrap();
    let height = fixture.native.chain.height();
    let mut peers = UnavailablePeers::start(&fixture.prepared);
    assert!(matches!(
        fixture
            .owner
            .read_current(&fixture.policy.binding, &verifier, Instant::now()),
        Err(crate::managed::Error::NativeDeadline)
    ));
    assert!(peers.requests.lock().unwrap().is_empty());

    // The unchanged original native cut is retryable under the fixture's original deadline.
    // Unavailable transport remains refusal; it cannot manufacture a current custody proof.
    let error = fixture
        .owner
        .read_current(&fixture.policy.binding, &verifier, fixture.options.deadline)
        .unwrap_err();
    assert!(!matches!(&error, crate::managed::Error::NativeDeadline));
    assert!(!peers.requests.lock().unwrap().is_empty());
    assert!(
        peers
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|request| request.method == "GET")
    );
    assert_eq!(verifier.checkpoint().encode_canonical().unwrap(), original);
    assert_eq!(fixture.native.chain.height(), height);
    peers.finish();
}
