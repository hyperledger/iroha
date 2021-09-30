#![allow(clippy::restriction, clippy::nursery)]

use std::thread;

use iroha::config::Configuration;
use iroha_crypto::Hash;
use iroha_data_model::{
    events::pipeline::{self, EntityType, Status},
    prelude::*,
};
use test_network::*;

fn tx_event(hash: Hash, status: Status) -> Event {
    Event::Pipeline(pipeline::Event {
        hash,
        entity_type: EntityType::Transaction,
        status,
    })
}

#[test]
fn status_workload_test() {
    let (_rt, _network, mut cl) = <Network>::start_test_with_runtime(4, 1);
    let pipeline_time = Configuration::pipeline_time();
    iroha_logger::error!("Client {:?}", cl);
    thread::sleep(pipeline_time * 5);

    let register = RegisterBox::new(IdentifiableBox::AssetDefinition(
        AssetDefinition::new_quantity("xor#wonderland".parse().unwrap()).into(),
    ));
    cl.submit(register).unwrap();
    thread::sleep(pipeline_time * 5);

    let mint = MintBox::new(
        Value::U32(1),
        IdBox::AssetId(AssetId::new(
            "xor#wonderland".parse().unwrap(),
            "alice@wonderland".parse().unwrap(),
        )),
    );
    let mut events = cl
        .listen_for_events(EventFilter::Pipeline(pipeline::EventFilter::by_entity(
            EntityType::Transaction,
        )))
        .unwrap();

    for i in 0..100 {
        iroha_logger::error!("iter {}", i);
        let hash = cl.submit(mint.clone()).unwrap();
        iroha_logger::error!("iter {} {}", i, hash);
        assert_eq!(
            events.next().unwrap().unwrap(),
            tx_event(hash, Status::Validating)
        );
        iroha_logger::error!("assert");
        let ev = events.next().unwrap().unwrap();
        iroha_logger::error!("rcv {:?}", ev);
        assert_eq!(ev, tx_event(hash, Status::Committed));
    }
}
