#![allow(clippy::unwrap_used)]
use std::{
    fmt::Debug,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
};

use iroha_actor::{broker::*, prelude::*};
use iroha_logger::{
    config::{LevelEnv, LoggerConfiguration},
    info,
};
use iroha_p2p::{peer::PeerId, *};
use parity_scale_codec::{Decode, Encode};
use tokio::time::Duration;

#[derive(iroha_actor::Message, Clone, Debug, Decode, Encode)]
struct TestMessage(String);

fn gen_address() -> String {
    format!("127.0.0.1:{}", unique_port::get_unique_free_port().unwrap())
}

/// This test creates a network and one peer.
/// This peer connects back to our network, emulating some distant peer.
/// There is no need to create separate networks to check that messages
/// are properly sent and received using encryption and serialization/deserialization.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn network_create() {
    let log_config = LoggerConfiguration {
        max_log_level: LevelEnv::TRACE,
        compact_mode: false,
        ..LoggerConfiguration::default()
    };
    drop(iroha_logger::init(log_config));
    info!("Starting network tests...");
    let address = gen_address();
    let broker = Broker::new();
    let network = Network::<TestMessage>::new(broker.clone(), address.clone())
        .await
        .unwrap();
    drop(network.start().await);
    tokio::time::sleep(Duration::from_millis(200)).await;

    info!("Connecting to peer...");
    let peer1 = PeerId {
        address: address.clone(),
        public_key: None,
    };
    broker.issue_send(Connect { id: peer1.clone() }).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    info!("Posting message...");
    broker
        .issue_send(Post {
            data: TestMessage("Some data to send to peer".to_owned()),
            id: peer1,
        })
        .await;

    tokio::time::sleep(Duration::from_millis(200)).await;
}

#[derive(Debug)]
pub struct TestActor {
    broker: Broker,
    messages: Arc<AtomicU32>,
}

#[async_trait::async_trait]
impl Actor for TestActor {
    async fn on_start(&mut self, ctx: &mut Context<Self>) {
        self.broker.subscribe::<TestMessage, _>(ctx);
    }
}

#[async_trait::async_trait]
impl Handler<TestMessage> for TestActor {
    type Result = ();

    async fn handle(&mut self, msg: TestMessage) -> Self::Result {
        info!("Actor got message {:?}", msg);
        let _ = self.messages.fetch_add(1, Ordering::Relaxed);
    }
}

/// This test creates two networks and one peer from the first network.
/// This peer connects to our second network, emulating some distant peer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_networks() {
    let delay = Duration::from_millis(200);
    let log_config = LoggerConfiguration {
        max_log_level: LevelEnv::TRACE,
        compact_mode: false,
        ..LoggerConfiguration::default()
    };
    drop(iroha_logger::init(log_config));
    info!("Starting first network...");
    let address1 = gen_address();

    let broker1 = Broker::new();
    let network1 = Network::<TestMessage>::new(broker1.clone(), address1.clone())
        .await
        .unwrap();
    drop(network1.start().await);
    tokio::time::sleep(delay).await;

    info!("Starting second network...");
    let address2 = gen_address();
    let broker2 = Broker::new();
    let network2 = Network::<TestMessage>::new(broker2.clone(), address2.clone())
        .await
        .unwrap();
    drop(network2.start().await);
    tokio::time::sleep(delay).await;

    let messages2 = Arc::new(AtomicU32::new(0));
    let actor2 = TestActor {
        broker: broker2.clone(),
        messages: Arc::clone(&messages2),
    };
    drop(actor2.start().await);
    tokio::time::sleep(delay).await;

    info!("Connecting to peer...");
    let peer2 = PeerId {
        address: address2.clone(),
        public_key: None,
    };
    // Connecting to second peer from network1
    broker1.issue_send(Connect { id: peer2.clone() }).await;
    tokio::time::sleep(delay).await;

    info!("Posting message...");
    broker1
        .issue_send(Post {
            data: TestMessage("Some data to send to peer".to_owned()),
            id: peer2,
        })
        .await;

    tokio::time::sleep(delay).await;
    assert_eq!(messages2.load(Ordering::Relaxed), 1);
}

#[test]
fn test_encryption() {
    use ursa::encryption::symm::prelude::*;

    const TEST_KEY: [u8; 32] = [
        5, 87, 82, 183, 220, 57, 107, 49, 227, 4, 96, 231, 198, 88, 153, 11, 22, 65, 56, 45, 237,
        35, 231, 165, 122, 153, 14, 68, 13, 84, 5, 24,
    ];

    let encryptor = SymmetricEncryptor::<ChaCha20Poly1305>::new_with_key(&TEST_KEY).unwrap();
    let message = b"Some ciphertext";
    let aad = b"Iroha2 AAD";
    let res = encryptor.encrypt_easy(aad.as_ref(), message.as_ref());
    assert!(res.is_ok());

    let ciphertext = res.unwrap();
    let res = encryptor.decrypt_easy(aad.as_ref(), ciphertext.as_slice());
    assert!(res.is_ok());
    assert_eq!(res.unwrap().as_slice(), message);
}
