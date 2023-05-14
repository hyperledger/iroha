#![allow(clippy::restriction)]

use std::thread::{self, JoinHandle};

use eyre::Result;
use iroha_data_model::{
    parameter::{default::MAX_TRANSACTIONS_IN_BLOCK, ParametersBuilder},
    prelude::*,
};
use test_network::*;

use super::Configuration;

// Needed to re-enable ignored tests.
#[allow(dead_code)]
const PEER_COUNT: usize = 7;

#[test]
fn transaction_with_no_instructions_should_be_committed() -> Result<()> {
    test_with_instruction_and_status_and_port(None, PipelineStatusKind::Committed, 10_250)
}

#[test]
fn transaction_with_fail_instruction_should_be_rejected() -> Result<()> {
    let fail = FailBox::new("Should be rejected");
    test_with_instruction_and_status_and_port(
        Some(fail.into()),
        PipelineStatusKind::Rejected,
        10_350,
    )
}

#[allow(dead_code, clippy::needless_range_loop, clippy::needless_pass_by_value)]
fn test_with_instruction_and_status_and_port(
    instruction: Option<InstructionBox>,
    should_be: PipelineStatusKind,
    port: u16,
) -> Result<()> {
    let (_rt, network, client) =
        <Network>::start_test_with_runtime(PEER_COUNT.try_into().unwrap(), Some(port));
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
    let hash = transaction.hash();
    let mut handles = Vec::new();
    for listener in clients {
        let checker = Checker { listener, hash };
        let handle_validating = checker.clone().spawn(PipelineStatusKind::Validating);
        handles.push(handle_validating);
        let handle_validated = checker.spawn(should_be);
        handles.push(handle_validated);
    }
    // When
    submitter.submit_transaction(transaction)?;
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
    hash: iroha_crypto::HashOf<SignedTransaction>,
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
