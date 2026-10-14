//! Integration test scaffold for pipeline `BlockStatus::Rejected` events via Torii.
//!
//! This stays `#[ignore]` until a deterministic rejection trigger is wired into the
//! harness. Run with `IROHA_RUN_IGNORED=1 cargo test -p integration_tests pipeline_block_rejected -- --ignored`.
use eyre::Result;
use futures_util::StreamExt;
use integration_tests::sandbox;
use iroha::data_model::events::{
    EventBox,
    pipeline::{BlockEventFilter, BlockStatus, PipelineEventBox, PipelineEventFilterBox},
};
use iroha_test_network::NetworkBuilder;
#[tokio::test]
#[ignore = "awaiting deterministic rejection trigger; set IROHA_RUN_IGNORED=1 to exercise"]
async fn emits_block_rejected_event() -> Result<()> {
    if std::env::var("IROHA_RUN_IGNORED").ok().as_deref() != Some("1") {
        eprintln!(
            "Skipping: needs deterministic rejection trigger in harness. Set IROHA_RUN_IGNORED=1 to run."
        );
        return Ok(());
    }
    // Start a small network
    let Some(network) = sandbox::start_network_async_or_skip(
        NetworkBuilder::new().with_min_peers(4),
        stringify!(emits_block_rejected_event),
    )
    .await?
    else {
        return Ok(());
    };
    // Build a client against the primary peer
    let client = network.client();
    // Subscribe to pipeline Block events with status == Rejected
    let filter =
        PipelineEventFilterBox::from(BlockEventFilter::new().for_status(BlockStatus::Rejected(
            iroha_data_model::block::error::BlockRejectionReason::ConsensusBlockRejection,
        )));
    let mut events = client
        .account_client()
        .events()
        .subscribe([filter])
        .await
        .expect("events subscription")
        .take(1);
    // Future work: induce a deterministic rejection.
    // Option A: Kill peer[1] and attempt to force a block creation on peer[0]
    // (e.g., by submitting enough transactions to fill the block and waiting
    // for the deadline). Consensus may decide to wait rather than reject, so
    // this approach can be flaky and requires tuning block/commit times.
    //
    // Option B: Inject a bad block header into peer[1]'s store (soft-fork)
    // and observe peer[1] emitting a rejection during sync. This needs a
    // helper in `iroha_test_network` to write a crafted block prior to startup
    // or while paused.
    //
    // For now, we just outline the call; implementers can replace this with
    // a concrete trigger once available:
    // network.peers()[1].kill().await.expect("kill peer");
    // submit_transactions_to_fill_block(&client).await;
    // Expect one rejected block event
    if let Some(Ok(ev)) = events.next().await {
        match ev {
            EventBox::Pipeline(PipelineEventBox::Block(b)) => {
                assert!(matches!(b.status, BlockStatus::Rejected(_)));
            }
            other => panic!("unexpected event: {other:?}"),
        }
    } else {
        panic!("no rejected block event received");
    }
    Ok(())
}
