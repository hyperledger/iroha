#![allow(clippy::restriction)]

use std::thread::{self, JoinHandle};

use eyre::Result;
use iroha_data_model::prelude::*;
use test_network::*;

use super::Configuration;

const PEER_COUNT: usize = 7;

#[test]
fn transaction_with_no_instructions_should_be_committed() -> Result<()> {
    test_with_instruction_and_status(None, PipelineStatusKind::Committed)
}

#[test]
fn transaction_with_fail_instruction_should_be_rejected() -> Result<()> {
    let fail = FailBox::new("Should be rejected");
    test_with_instruction_and_status(Some(fail.into()), PipelineStatusKind::Rejected)
}

#[allow(clippy::needless_range_loop, clippy::needless_pass_by_value)]
fn test_with_instruction_and_status(
    instruction: Option<Instruction>,
    should_be: PipelineStatusKind,
) -> Result<()> {
    let (_rt, network, genesis_client) =
        <Network>::start_test_with_runtime(PEER_COUNT.try_into().unwrap(), 1);
    let clients = network.clients();
    wait_for_genesis_committed(&clients, 0);
    let pipeline_time = Configuration::pipeline_time();
    // Given
    let submitter = genesis_client;
    let transaction = submitter.build_transaction(instruction.into(), UnlimitedMetadata::new())?;
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
    hash: iroha_crypto::HashOf<Transaction>,
}

impl Checker {
    fn spawn(mut self, status_kind: PipelineStatusKind) -> JoinHandle<()> {
        thread::spawn(move || {
            let mut event_iterator = self
                .listener
                .listen_for_events(EventFilter::Pipeline(
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
