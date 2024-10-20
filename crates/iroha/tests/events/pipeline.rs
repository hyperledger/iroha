use std::time::Duration;

use eyre::Result;
use futures_util::StreamExt;
use iroha::data_model::{
    events::pipeline::{TransactionEventFilter, TransactionStatus},
    isi::error::InstructionExecutionError,
    prelude::*,
    query::error::FindError,
    transaction::error::TransactionRejectionReason,
    ValidationFail,
};
use iroha_test_network::*;
use tokio::{task::spawn_blocking, time::timeout};

#[tokio::test]
async fn transaction_with_ok_instruction_should_be_committed() -> Result<()> {
    let register = Register::domain(Domain::new("looking_glass".parse()?));
    test_with_instruction_and_status([register], &TransactionStatus::Approved).await
}

#[tokio::test]
async fn transaction_with_fail_instruction_should_be_rejected() -> Result<()> {
    let unknown_domain_id = "dummy".parse::<DomainId>()?;
    let fail_isi = Unregister::domain(unknown_domain_id.clone());

    test_with_instruction_and_status(
        [fail_isi],
        &TransactionStatus::Rejected(Box::new(TransactionRejectionReason::Validation(
            ValidationFail::InstructionFailed(InstructionExecutionError::Find(FindError::Domain(
                unknown_domain_id,
            ))),
        ))),
    )
    .await
}

async fn test_with_instruction_and_status(
    exec: impl Into<Executable> + Send,
    should_be: &TransactionStatus,
) -> Result<()> {
    // Given
    let network = NetworkBuilder::new().start().await?;
    let client = network.client();

    // When
    let transaction = client.build_transaction(exec, Metadata::default());
    let hash = transaction.hash();
    let mut events = client
        .listen_for_events_async([TransactionEventFilter::default().for_hash(hash)])
        .await?;
    spawn_blocking(move || client.submit_transaction(&transaction)).await??;

    // Then
    timeout(Duration::from_secs(5), async move {
        let EventBox::Pipeline(PipelineEventBox::Transaction(event)) =
            events.next().await.unwrap().unwrap()
        else {
            panic!("Expected transaction event");
        };
        assert_eq!(*event.status(), TransactionStatus::Queued);

        let EventBox::Pipeline(PipelineEventBox::Transaction(event)) =
            events.next().await.unwrap().unwrap()
        else {
            panic!("Expected transaction event");
        };

        assert_eq!(event.status(), should_be);
    })
    .await?;

    Ok(())
}

#[test]
#[ignore = "TODO: implement with the help of Kura Inspector, "]
fn applied_block_must_be_available_in_kura() {
    unimplemented!("Take a look at previous implementation and restore this test");
}
