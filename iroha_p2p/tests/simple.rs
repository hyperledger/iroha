#![allow(clippy::unwrap_used)]
use std::{
    fmt::Debug,
    str::FromStr,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
};

use futures::future::join_all;
use iroha_actor::{broker::*, prelude::*};
use iroha_crypto::{KeyPair, PublicKey};
use iroha_logger::{
    config::{LevelEnv, LoggerConfiguration},
    info,
};
use iroha_p2p::*;
use parity_scale_codec::{Decode, Encode};
use tokio::time::Duration;

#[derive(Clone, Debug, Decode, Encode)]
struct TestMessage(String);

fn gen_address() -> String {
    format!("127.0.0.1:{}", unique_port::get_unique_free_port().unwrap())
}

#[derive(Debug)]
pub struct TestActor {
    broker: Broker,
    messages: Arc<AtomicU32>,
}

#[async_trait::async_trait]
impl Actor for TestActor {
    async fn on_start(&mut self, ctx: &mut Context<Self>) {
        self.broker.subscribe::<Received<TestMessage>, _>(ctx);
    }
}

#[async_trait::async_trait]
impl Handler<Received<TestMessage>> for TestActor {
    type Result = ();

    async fn handle(&mut self, msg: Received<TestMessage>) -> Self::Result {
        info!("Actor got message {:?}", msg);
        let _ = self.messages.fetch_add(1, Ordering::SeqCst);
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
    iroha_logger::init(log_config);
    let public_key1 = iroha_crypto::KeyPair::generate().unwrap().public_key;
    let public_key2 = iroha_crypto::KeyPair::generate().unwrap().public_key;

    info!("Starting first network...");
    let address1 = gen_address();

    let broker1 = Broker::new();
    let network1 =
        Network::<TestMessage>::new(broker1.clone(), address1.clone(), public_key1.clone())
            .await
            .unwrap();
    let network1 = network1.start().await;
    tokio::time::sleep(delay).await;

    info!("Starting second network...");
    let address2 = gen_address();
    let broker2 = Broker::new();
    let network2 =
        Network::<TestMessage>::new(broker2.clone(), address2.clone(), public_key2.clone())
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
    network1.do_send(Connect { id: peer2.clone() }).await;
    tokio::time::sleep(delay * 10).await;

    info!("Posting message...");
    network1
        .do_send(Post {
            data: TestMessage("Some data to send to peer".to_owned()),
            id: peer2.clone(),
        })
        .await;

    tokio::time::sleep(delay * 10).await;
    assert_eq!(messages2.load(Ordering::SeqCst), 1);

    let connected_peers: Connected = network1.send(GetConnected).await.unwrap();
    assert_eq!(connected_peers.peers.len(), 1);

    let connected_peers: Connected = network2.send(GetConnected).await.unwrap();
    assert_eq!(connected_peers.peers.len(), 1);

    info!("Connecting to the same peer from network1");
    network1.do_send(Connect { id: peer2.clone() }).await;
    tokio::time::sleep(delay).await;

    let connected_peers: Connected = network1.send(GetConnected).await.unwrap();
    let connected_peers2: Connected = network2.send(GetConnected).await.unwrap();
    assert_eq!(
        (connected_peers.peers.len(), connected_peers2.peers.len()),
        (1, 1)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn multiple_networks() {
    let log_config = LoggerConfiguration {
        max_log_level: LevelEnv::TRACE,
        compact_mode: false,
        ..LoggerConfiguration::default()
    };
    drop(iroha_logger::init(log_config));
    iroha_logger::info!("Starting...");

    let delay = Duration::from_millis(200);
    tokio::time::sleep(delay).await;

    let peers = std::iter::repeat_with(gen_address)
        .take(10)
        .collect::<Vec<_>>();

    let messages = Arc::new(AtomicU32::new(0));
    let futures = peers
        .iter()
        .map(|addr| start_network(addr.clone(), peers.clone(), Arc::clone(&messages)))
        .collect::<Vec<_>>();

    let (addrs, peer_ids): (Vec<_>, Vec<_>) = join_all(futures)
        .await
        .into_iter()
        .map(|(address, actor, public_key)| {
            (
                actor,
                PeerId {
                    address,
                    public_key,
                },
            )
        })
        .unzip();

    tokio::time::sleep(delay * 3).await;

    iroha_logger::info!("Sending posts...");
    for a in &addrs {
        for id in &peer_ids {
            let post = Post {
                data: TestMessage(String::from("Some data to send to peer")),
                id: id.clone(),
            };
            a.do_send(post).await;
            tokio::time::sleep(delay).await;
        }
    }
    iroha_logger::info!("Posts sent");
    tokio::time::sleep(delay * 10).await;

    assert_eq!(messages.load(Ordering::SeqCst), 90);
}

async fn start_network(
    addr: String,
    peers: Vec<String>,
    messages: Arc<AtomicU32>,
) -> (String, Addr<Network<TestMessage>>, PublicKey) {
    info!("Starting network on {}...", &addr);

    let keypair = KeyPair::generate().unwrap();
    let broker = Broker::new();
    // This actor will get the messages from other peers and increment the counter
    let actor = TestActor {
        broker: broker.clone(),
        messages,
    };
    drop(actor.start().await);

    let network =
        Network::<TestMessage>::new(broker.clone(), addr.clone(), keypair.public_key.clone())
            .await
            .unwrap();
    let network = network.start().await;
    //
    // The most needed delay!!!
    let delay: u64 = rand::random();
    tokio::time::sleep(Duration::from_millis(250 + (delay % 500))).await;

    let mut count = 0;
    let mut test_count = 0;

    for p in &peers {
        if *p != addr {
            let peer = PeerId {
                address: p.clone(),
                public_key: keypair.public_key.clone(),
            };

            network.do_send(Connect { id: peer }).await;
            count += 1;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    tokio::time::sleep(Duration::from_secs(5)).await;

    while !matches!(network.send(GetConnected).await, Ok(result) if result.peers.len() == count) {
        dbg!(network.send(GetConnected).await);
        tokio::time::sleep(Duration::from_millis(1000)).await;
    }
    info!(%addr, "Got all {} connections!", count);

    (addr, network, keypair.public_key.clone())
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
