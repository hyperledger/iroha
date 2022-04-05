#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic_in_result_fn)]

use std::{sync::mpsc, thread};

use eyre::Result;
use iroha_core::smartcontracts::wasm;
use iroha_data_model::{prelude::*, transaction::WasmSmartContract};
use parity_scale_codec::Encode;
use test_network::{Peer as TestPeer, *};

use super::Configuration;
use crate::wasm::utils::wasm_template;

fn produce_instructions() -> Vec<Instruction> {
    let domains = (0..4)
        .map(|domain_index: usize| Domain::new(domain_index.to_string().parse().expect("Valid")));

    let registers: [Instruction; 4] = domains
        .into_iter()
        .map(RegisterBox::new)
        .map(Instruction::from)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    // TODO: should we re-introduce the DSL?
    vec![
        // domain "0"
        // pair
        //      domain "1"
        //      if false fail else sequence
        //          domain "2"
        //          domain "3"
        registers[0].clone(),
        Pair::new::<Instruction, _>(
            registers[1].clone(),
            IfInstruction::with_otherwise(
                false,
                FailBox::new("unreachable"),
                SequenceBox::new(vec![registers[2].clone(), registers[3].clone()]),
            ),
        )
        .into(),
    ]
}

#[test]
fn instruction_execution_should_produce_events() -> Result<()> {
    let instructions = produce_instructions().into();
    transaction_execution_should_produce_events(instructions)
}

#[test]
fn wasm_execution_should_produce_events() -> Result<()> {
    let isi_hex: Vec<String> = produce_instructions()
        .into_iter()
        .map(|isi| isi.encode())
        .map(hex::encode)
        .collect();

    let mut ptr_offset = 0;
    let mut isi_calls = String::new();
    for isi in &isi_hex {
        let ptr_len = isi.len();

        // It's expected that hex values are of even length
        #[allow(clippy::integer_division)]
        isi_calls.push_str(&format!(
            "(call $exec_isi (i32.const {ptr_offset}) (i32.const {ptr_len}))",
            ptr_offset = ptr_offset / 2,
            ptr_len = ptr_len / 2,
        ));

        ptr_offset = ptr_len;
    }

    let wat = format!(
        r#"
        (module
            {wasm_template}

            ;; Function which starts the smartcontract execution
            (func (export "{main_fn_name}") (param i32 i32)
                {isi_calls}))
        "#,
        main_fn_name = wasm::WASM_MAIN_FN_NAME,
        wasm_template = wasm_template(&isi_hex.concat()),
        isi_calls = isi_calls
    );

    transaction_execution_should_produce_events(Executable::Wasm(WasmSmartContract {
        raw_data: wat.into_bytes(),
    }))
}

fn transaction_execution_should_produce_events(executable: Executable) -> Result<()> {
    let (_rt, _peer, client) = <TestPeer>::start_test_with_runtime();
    wait_for_genesis_committed(&vec![client.clone()], 0);

    let pipeline_time = Configuration::pipeline_time();

    // spawn event reporter
    let mut listener = client.clone();
    let (init_sender, init_receiver) = mpsc::channel();
    let (event_sender, event_receiver) = mpsc::channel();
    let event_filter = DataEventFilter::AcceptAll.into();
    thread::spawn(move || -> Result<()> {
        let event_iterator = listener.listen_for_events(event_filter)?;
        init_sender.send(())?;
        for event in event_iterator {
            event_sender.send(event)?
        }
        Ok(())
    });

    // submit transaction to produce events
    init_receiver.recv()?;
    let transaction = client
        .build_transaction(executable, UnlimitedMetadata::new())
        .unwrap();
    client.submit_transaction(transaction)?;
    thread::sleep(pipeline_time * 2);

    // assertion
    for i in 0..4_usize {
        let domain_id = DomainId::new(i.to_string().parse().expect("Valid"));
        let expected_event = DomainEvent::Created(domain_id).into();
        let event: DataEvent = event_receiver.recv()??.try_into()?;
        assert_eq!(event, expected_event);
    }

    Ok(())
}
