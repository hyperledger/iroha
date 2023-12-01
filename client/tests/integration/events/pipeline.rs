use std::thread::{self, JoinHandle};

use eyre::Result;
use iroha_client::{
    crypto::HashOf,
    data_model::{
        parameter::{default::MAX_TRANSACTIONS_IN_BLOCK, ParametersBuilder},
        prelude::*,
    },
};
use iroha_config::iroha::Configuration;
use test_network::*;

// Needed to re-enable ignored tests.
#[allow(dead_code)]
const PEER_COUNT: usize = 7;

#[ignore = "ignore, more in #2851"]
#[test]
fn transaction_with_no_instructions_should_be_committed() -> Result<()> {
    test_with_instruction_and_status_and_port(None, PipelineStatusKind::Committed, 10_250)
}

#[ignore = "ignore, more in #2851"]
// #[ignore = "Experiment"]
#[test]
fn transaction_with_fail_instruction_should_be_rejected() -> Result<()> {
    let fail = Fail::new("Should be rejected");
    test_with_instruction_and_status_and_port(
        Some(fail.into()),
        PipelineStatusKind::Rejected,
        10_350,
    )
}

#[allow(dead_code, clippy::needless_range_loop, clippy::needless_pass_by_value)]
fn test_with_instruction_and_status_and_port(
    instruction: Option<InstructionExpr>,
    should_be: PipelineStatusKind,
    port: u16,
) -> Result<()> {
    let (_rt, network, client) =
        Network::start_test_with_runtime(PEER_COUNT.try_into().unwrap(), Some(port));
    let clients = network.clients();
    wait_for_genesis_committed(&clients, 0);
    let pipeline_time = Configuration::pipeline_time();

    client.submit_blocking(
        ParametersBuilder::new()
            .add_parameter(MAX_TRANSACTIONS_IN_BLOCK, 1u32)?
            .into_set_parameters(),
    )?;

    // Given
    let submitter = client;
    let transaction = submitter.build_transaction(instruction, UnlimitedMetadata::new())?;
    let hash = transaction.payload().hash();
    let mut handles = Vec::new();
    for listener in clients {
        let checker = Checker { listener, hash };
        let handle_validating = checker.clone().spawn(PipelineStatusKind::Validating);
        handles.push(handle_validating);
        let handle_validated = checker.spawn(should_be);
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
    hash: HashOf<TransactionPayload>,
}

impl Checker {
    fn spawn(self, status_kind: PipelineStatusKind) -> JoinHandle<()> {
        thread::spawn(move || {
            let mut event_iterator = self
                .listener
                .listen_for_events(FilterBox::Pipeline(
                    PipelineEventFilter::new()
                        .entity_kind(PipelineEntityKind::Transaction)
                        .status_kind(status_kind)
                        .hash(*self.hash),
                ))
                .expect("Failed to create event iterator.");
            let event_result = event_iterator.next().expect("Stream closed");
            let _event = event_result.expect("Must be valid");
        })
    }
}

#[test]
fn committed_block_must_be_available_in_kura() {
    let (_rt, peer, client) = <PeerBuilder>::new().with_port(11_040).start_with_runtime();
    wait_for_genesis_committed(&[client.clone()], 0);

    let event_filter = PipelineEventFilter::new()
        .entity_kind(PipelineEntityKind::Block)
        .status_kind(PipelineStatusKind::Committed)
        .into();
    let mut event_iter = client
        .listen_for_events(event_filter)
        .expect("Failed to subscribe for events");

    client
        .submit(Fail::new("Dummy instruction"))
        .expect("Failed to submit transaction");

    let event = event_iter.next().expect("Block must be committed");
    let Ok(Event::Pipeline(PipelineEvent {
        entity_kind: PipelineEntityKind::Block,
        status: PipelineStatus::Committed,
        hash,
    })) = event
    else {
        panic!("Received unexpected event")
    };
    let hash = HashOf::from_untyped_unchecked(hash);

    peer.iroha
        .as_ref()
        .expect("Must be some")
        .kura
        .get_block_height_by_hash(&hash)
        .expect("Block committed event was received earlier");
}
