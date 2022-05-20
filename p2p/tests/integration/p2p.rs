#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    fmt::Debug,
    str::FromStr,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, Once,
    },
};

use futures::{prelude::*, stream::FuturesUnordered};
use iroha_actor::{broker::*, prelude::*};
use iroha_config::logger;
use iroha_crypto::{KeyPair, PublicKey};
use iroha_logger::{prelude::*, Configuration, Level};
use iroha_p2p::{
    network::{ConnectedPeers, GetConnectedPeers},
    peer::PeerId,
    *,
};
use parity_scale_codec::{Decode, Encode};
use tokio::time::Duration;

#[derive(iroha_actor::Message, Clone, Debug, Decode, Encode)]
struct TestMessage(String);

fn gen_address() -> String {
    format!("127.0.0.1:{}", unique_port::get_unique_free_port().unwrap())
}

static INIT: Once = Once::new();

fn setup_logger() {
    INIT.call_once(|| {
        let log_config = Configuration {
            max_log_level: Level(logger::Level::TRACE).into(),
            compact_mode: false,
            ..Configuration::default()
        };
        iroha_logger::init(&log_config).expect("Failed to start logger");
    })
}

/// This test creates a network and one peer.
/// This peer connects back to our network, emulating some distant peer.
/// There is no need to create separate networks to check that messages
/// are properly sent and received using encryption and serialization/deserialization.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn network_create() {
    let delay = Duration::from_millis(200);
    setup_logger();
    info!("Starting network tests...");
    let address = gen_address();
    let broker = Broker::new();
    let public_key = iroha_crypto::PublicKey::from_str(
        "ed01207233bfc89dcbd68c19fde6ce6158225298ec1131b6a130d1aeb454c1ab5183c0",
    )
    .unwrap();
    let network =
        Network::<TestMessage>::new(broker.clone(), address.clone(), public_key.clone(), 100)
            .await
            .unwrap();
    network.start().await;
    tokio::time::sleep(delay).await;

    info!("Connecting to peer...");
    let peer1 = PeerId {
        address: address.clone(),
        public_key: public_key.clone(),
    };
    broker
        .issue_send(ConnectPeer {
            address: peer1.address.clone(),
        })
        .await;
    tokio::time::sleep(delay).await;

    info!("Posting message...");
    broker
        .issue_send(Post {
            data: TestMessage("Some data to send to peer".to_owned()),
            peer: peer1,
        })
        .await;

    tokio::time::sleep(delay).await;
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
        info!(?msg, "Actor received message");
        let _ = self.messages.fetch_add(1, Ordering::SeqCst);
    }
}

/// This test creates two networks and one peer from the first network.
/// This peer connects to our second network, emulating some distant peer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_networks() {
    let delay = Duration::from_millis(200);
    setup_logger();
    let public_key1 = iroha_crypto::PublicKey::from_str(
        "ed01207233bfc89dcbd68c19fde6ce6158225298ec1131b6a130d1aeb454c1ab5183c0",
    )
    .unwrap();
    let public_key2 = iroha_crypto::PublicKey::from_str(
        "ed01207233bfc89dcbd68c19fde6ce6158225298ec1131b6a130d1aeb454c1ab5183c1",
    )
    .unwrap();
    info!("Starting first network...");
    let address1 = gen_address();

    let broker1 = Broker::new();
    let network1 =
        Network::<TestMessage>::new(broker1.clone(), address1.clone(), public_key1.clone(), 100)
            .await
            .unwrap();
    let network1 = network1.start().await;
    tokio::time::sleep(delay).await;

    info!("Starting second network...");
    let address2 = gen_address();
    let broker2 = Broker::new();
    let network2 =
        Network::<TestMessage>::new(broker2.clone(), address2.clone(), public_key2.clone(), 100)
            .await
            .unwrap();
    let network2 = network2.start().await;
    tokio::time::sleep(delay).await;

    let messages2 = Arc::new(AtomicU32::new(0));
    let actor2 = TestActor {
        broker: broker2.clone(),
        messages: Arc::clone(&messages2),
    };
    actor2.start().await;
    tokio::time::sleep(delay).await;

    info!("Connecting to peer...");
    let peer2 = PeerId {
        address: address2.clone(),
        public_key: public_key2,
    };
    // Connecting to second peer from network1
    broker1
        .issue_send(ConnectPeer {
            address: peer2.address.clone(),
        })
        .await;
    tokio::time::sleep(delay).await;

    info!("Posting message...");
    broker1
        .issue_send(Post {
            data: TestMessage("Some data to send to peer".to_owned()),
            peer: peer2.clone(),
        })
        .await;

    tokio::time::sleep(delay).await;
    assert_eq!(messages2.load(Ordering::SeqCst), 1);

    let connected_peers1: ConnectedPeers = network1.send(GetConnectedPeers).await.unwrap();
    assert_eq!(connected_peers1.peers.len(), 1);

    let connected_peers2: ConnectedPeers = network2.send(GetConnectedPeers).await.unwrap();
    assert_eq!(connected_peers2.peers.len(), 1);

    // Connecting to the same peer from network1
    broker1
        .issue_send(ConnectPeer {
            address: peer2.address.clone(),
        })
        .await;
    tokio::time::sleep(delay).await;

    let connected_peers: ConnectedPeers = network1.send(GetConnectedPeers).await.unwrap();
    assert_eq!(connected_peers.peers.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn multiple_networks() {
    let log_config = Configuration {
        max_log_level: Level(logger::Level::TRACE).into(),
        compact_mode: false,
        ..Configuration::default()
    };
    drop(iroha_logger::init(&log_config));
    info!("Starting...");

    let delay = Duration::from_millis(200);
    tokio::time::sleep(delay).await;

    let mut peers = Vec::new();
    for _ in 0_i32..10_i32 {
        let addr = gen_address();
        peers.push(addr);
    }

    let mut brokers = Vec::new();
    let mut peer_ids = Vec::new();
    let msgs = Arc::new(AtomicU32::new(0));
    peers
        .iter()
        .map(|addr| start_network(addr.clone(), peers.clone(), Arc::clone(&msgs)))
        .collect::<FuturesUnordered<_>>()
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .for_each(|(address, broker, public_key)| {
            brokers.push(broker);
            let peer_id = PeerId {
                address,
                public_key,
            };
            peer_ids.push(peer_id);
        });

    tokio::time::sleep(delay * 3).await;

    info!("Sending posts...");
    for b in &brokers {
        for id in &peer_ids {
            let post = Post {
                data: TestMessage(String::from("Some data to send to peer")),
                peer: id.clone(),
            };
            b.issue_send(post).await;
        }
    }
    info!("Posts sent");
    tokio::time::sleep(delay * 5).await;

    assert_eq!(msgs.load(Ordering::SeqCst), 90);
}

async fn start_network(
    addr: String,
    peers: Vec<String>,
    messages: Arc<AtomicU32>,
) -> (String, Broker, PublicKey) {
    info!(peer_addr = %addr, "Starting network");

    let keypair = KeyPair::generate().unwrap();
    let broker = Broker::new();
    // This actor will get the messages from other peers and increment the counter
    let actor = TestActor {
        broker: broker.clone(),
        messages,
    };
    drop(actor.start().await);

    let network = Network::<TestMessage>::new(
        broker.clone(),
        addr.clone(),
        keypair.public_key().clone(),
        100,
    )
    .await
    .unwrap();
    let network = network.start().await;
    // The most needed delay!!!
    let delay: u64 = rand::random();
    tokio::time::sleep(Duration::from_millis(250 + (delay % 500))).await;

    let mut conn_count = 0_usize;
    let mut test_count = 0_usize;
    for p in &peers {
        if *p != addr {
            let peer = PeerId {
                address: p.clone(),
                public_key: keypair.public_key().clone(),
            };

            broker
                .issue_send(ConnectPeer {
                    address: peer.address,
                })
                .await;
            conn_count += 1_usize;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    while let Ok(result) = network.send(iroha_p2p::network::GetConnectedPeers).await {
        let connections = result.peers.len();
        info!(peer_addr = %addr, %connections);
        if connections == conn_count || test_count >= 10_usize {
            break;
        }
        test_count += 1_usize;
        tokio::time::sleep(Duration::from_millis(1000)).await;
    }
    info!(peer_addr = %addr, %conn_count, "Got all connections!");

    (addr, broker, keypair.public_key().clone())
}

#[test]
fn test_encryption() {
    use iroha_crypto::ursa::encryption::symm::prelude::*;

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
    let res_cipher = encryptor.decrypt_easy(aad.as_ref(), ciphertext.as_slice());
    assert!(res_cipher.is_ok());
    assert_eq!(res_cipher.unwrap().as_slice(), message);
}
