use std::{sync::mpsc, thread};

use eyre::{eyre, Result};
use iroha_core::config::Configuration;
use iroha_data_model::prelude::*;
use test_network::{Peer as TestPeer, *};

#[test]
fn nested_instructions_are_flattened_into_data_events() -> Result<()> {
    let (_rt, _peer, mut client) = <TestPeer>::start_test_with_runtime();
    wait_for_genesis_committed(vec![client.clone()], 0);
    let pipeline_time = Configuration::pipeline_time();

    // spawn event reporter
    let mut listener = client.clone();
    let (init_sender, init_receiver) = mpsc::channel();
    let (event_sender, event_receiver) = mpsc::channel();
    let event_filter = DataEventFilter::default().into();
    thread::spawn(move || -> Result<()> {
        let event_iterator = listener.listen_for_events(event_filter)?;
        init_sender.send(())?;
        for event in event_iterator {
            event_sender.send(event)?
        }
        Ok(())
    });

    // submit instructions to produce events
    let domains: Vec<Domain> = (0..4)
        .map(|domain_index: usize| Domain::test(&domain_index.to_string()))
        .collect();
    let registers: [Instruction; 4] = domains
        .clone()
        .into_iter()
        .map(IdentifiableBox::from)
        .map(RegisterBox::new)
        .map(Instruction::from)
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_err| eyre!("unreachable"))?;
    let instructions = vec![
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
    ];
    init_receiver.recv()?;
    client.submit_all(instructions)?;
    thread::sleep(pipeline_time * 2);

    // assertion
    for tester in domains
        .into_iter()
        .map(Register::new)
        .map(DataEvent::from)
        .map(Event::from)
    {
        let testee = event_receiver.recv()??;
        if tester != testee {
            return Err(eyre!("expected: {:?}, actual: {:?}", tester, testee));
        }
    }

    Ok(())
}
