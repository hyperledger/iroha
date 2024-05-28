use std::thread::{self, JoinHandle};

use eyre::Result;
use iroha_client::{
    crypto::HashOf,
    data_model::{
        parameter::{default::MAX_TRANSACTIONS_IN_BLOCK, ParametersBuilder},
        prelude::*,
    },
};
use iroha_config::parameters::actual::Root as Config;
use iroha_data_model::{
    events::pipeline::{
        BlockEvent, BlockEventFilter, BlockStatus, TransactionEventFilter, TransactionStatus,
    },
    isi::error::InstructionExecutionError,
    transaction::error::TransactionRejectionReason,
    ValidationFail,
};
use test_network::*;

// Needed to re-enable ignored tests.
const PEER_COUNT: usize = 7;

#[ignore = "ignore, more in #2851"]
#[test]
fn transaction_with_no_instructions_should_be_committed() -> Result<()> {
    test_with_instruction_and_status_and_port(None, &TransactionStatus::Approved, 10_250)
}

#[ignore = "ignore, more in #2851"]
// #[ignore = "Experiment"]
#[test]
fn transaction_with_fail_instruction_should_be_rejected() -> Result<()> {
    let msg = "Should be rejected".to_owned();

    let fail = Fail::new(msg.clone());
    test_with_instruction_and_status_and_port(
        Some(fail.into()),
        &TransactionStatus::Rejected(Box::new(TransactionRejectionReason::Validation(
            ValidationFail::InstructionFailed(InstructionExecutionError::Fail(msg)),
        ))),
        10_350,
    )
}

fn test_with_instruction_and_status_and_port(
    instruction: Option<InstructionBox>,
    should_be: &TransactionStatus,
    port: u16,
) -> Result<()> {
    let (_rt, network, client) =
        Network::start_test_with_runtime(PEER_COUNT.try_into().unwrap(), Some(port));
    let clients = network.clients();
    wait_for_genesis_committed(&clients, 0);
    let pipeline_time = Config::pipeline_time();

    client.submit_all_blocking(
        ParametersBuilder::new()
            .add_parameter(MAX_TRANSACTIONS_IN_BLOCK, 1u32)?
            .into_set_parameters(),
    )?;

    // Given
    let submitter = client;
    let transaction = submitter.build_transaction(instruction, UnlimitedMetadata::new());
    let hash = transaction.hash();
    let mut handles = Vec::new();
    for listener in clients {
        let checker = Checker { listener, hash };
        let handle_validating = checker.clone().spawn(TransactionStatus::Queued);
        handles.push(handle_validating);
        let handle_validated = checker.spawn(should_be.clone());
        handles.push(handle_validated);
    }
    // When
    submitter.submit_transaction(&transaction)?;
    thread::sleep(pipeline_time * 2);
    // Then
    for handle in handles {
        handle.join().expect("Thread panicked")
    }
    Ok(())
}

#[derive(Clone)]
struct Checker {
    listener: iroha_client::client::Client,
    hash: HashOf<SignedTransaction>,
}

impl Checker {
    fn spawn(self, status_kind: TransactionStatus) -> JoinHandle<()> {
        thread::spawn(move || {
            let mut event_iterator = self
                .listener
                .listen_for_events([TransactionEventFilter::default()
                    .for_status(status_kind)
                    .for_hash(self.hash)])
                .expect("Failed to create event iterator.");
            let event_result = event_iterator.next().expect("Stream closed");
            let _event = event_result.expect("Must be valid");
        })
    }
}

#[test]
fn applied_block_must_be_available_in_kura() {
    let (_rt, peer, client) = <PeerBuilder>::new().with_port(11_040).start_with_runtime();
    wait_for_genesis_committed(&[client.clone()], 0);

    let event_filter = BlockEventFilter::default().for_status(BlockStatus::Applied);
    let mut event_iter = client
        .listen_for_events([event_filter])
        .expect("Failed to subscribe for events");

    client
        .submit(Fail::new("Dummy instruction".to_owned()))
        .expect("Failed to submit transaction");

    let event: BlockEvent = event_iter
        .next()
        .expect("Block must be committed")
        .expect("Block must be committed")
        .try_into()
        .expect("Received unexpected event");

    peer.irohad
        .as_ref()
        .expect("Must be some")
        .kura()
        .get_block_by_height(event.header().height())
        .expect("Block applied event was received earlier");
}
