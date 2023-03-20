#![allow(clippy::restriction)]

use std::{
    fmt::Debug,
    str::FromStr,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, Once,
    },
};

use futures::{prelude::*, stream::FuturesUnordered};
use iroha_config_base::proxy::Builder;
use iroha_crypto::{KeyPair, PublicKey};
use iroha_data_model::prelude::PeerId;
use iroha_logger::{prelude::*, Configuration, ConfigurationProxy, Level};
use iroha_p2p::{network::message::*, NetworkHandle};
use parity_scale_codec::{Decode, Encode};
use tokio::{sync::mpsc, time::Duration};

#[derive(Clone, Debug, Decode, Encode)]
struct TestMessage(String);

fn gen_address_with_port(port: u16) -> String {
    format!("127.0.0.1:{port}")
}

static INIT: Once = Once::new();

fn setup_logger() {
    INIT.call_once(|| {
        let log_config = Configuration {
            max_log_level: Level::TRACE.into(),
            compact_mode: false,
            ..ConfigurationProxy::default()
                .build()
                .expect("Default logger config failed to build. This is a programmer error")
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
    let address = gen_address_with_port(12_000);
    let public_key = iroha_crypto::PublicKey::from_str(
        "ed01 20 7233BFC89DCBD68C19FDE6CE6158225298EC1131B6A130D1AEB454C1AB5183C0",
    )
    .unwrap();
    let network = NetworkHandle::start(address.clone(), public_key.clone())
        .await
        .unwrap();
    tokio::time::sleep(delay).await;

    info!("Connecting to peer...");
    let peer1 = PeerId {
        address: address.clone(),
        public_key: public_key.clone(),
    };
    network
        .connect_peer(ConnectPeer {
            peer_id: peer1.clone(),
        })
        .await;
    tokio::time::sleep(delay).await;

    info!("Posting message...");
    network
        .post(Post {
            data: TestMessage("Some data to send to peer".to_owned()),
            peer_id: peer1,
        })
        .await;

    tokio::time::sleep(delay).await;
}

#[derive(Debug)]
pub struct TestActor {
    messages: Arc<AtomicU32>,
    receiver: mpsc::Receiver<TestMessage>,
}

impl TestActor {
    fn start(messages: Arc<AtomicU32>) -> mpsc::Sender<TestMessage> {
        let (sender, receiver) = mpsc::channel(10);
        let mut test_actor = Self { messages, receiver };
        tokio::task::spawn(async move {
            loop {
                tokio::select! {
                    Some(msg) = test_actor.receiver.recv() => {
                        info!(?msg, "Actor received message");
                        test_actor.messages.fetch_add(1, Ordering::SeqCst);
                    },
                    else => break,
                }
            }
        });
        sender
    }
}

/// This test creates two networks and one peer from the first network.
/// This peer connects to our second network, emulating some distant peer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_networks() {
    let delay = Duration::from_millis(200);
    setup_logger();
    let public_key1 = iroha_crypto::PublicKey::from_str(
        "ed01 207233BFC89DCBD68C19FDE6CE6158225298EC1131B6A130D1AEB454C1AB5183C0",
    )
    .unwrap();
    let public_key2 = iroha_crypto::PublicKey::from_str(
        "ed01 207233BFC89DCBD68C19FDE6CE6158225298EC1131B6A130D1AEB454C1AB5183C1",
    )
    .unwrap();
    info!("Starting first network...");
    let address1 = gen_address_with_port(12_005);

    let mut network1 = NetworkHandle::start(address1.clone(), public_key1.clone())
        .await
        .unwrap();
    tokio::time::sleep(delay).await;

    info!("Starting second network...");
    let address2 = gen_address_with_port(12_010);
    let mut network2 = NetworkHandle::start(address2.clone(), public_key2.clone())
        .await
        .unwrap();
    tokio::time::sleep(delay).await;

    let messages2 = Arc::new(AtomicU32::new(0));
    let actor2 = TestActor::start(Arc::clone(&messages2));
    network2.subscribe_to_peers_messages(actor2).await;
    tokio::time::sleep(delay).await;

    info!("Connecting to peer...");
    let peer2 = PeerId {
        address: address2.clone(),
        public_key: public_key2,
    };
    // Connecting to second peer from network1
    network1
        .connect_peer(ConnectPeer {
            peer_id: peer2.clone(),
        })
        .await;
    tokio::time::sleep(delay).await;

    info!("Posting message...");
    network1
        .post(Post {
            data: TestMessage("Some data to send to peer".to_owned()),
            peer_id: peer2.clone(),
        })
        .await;

    tokio::time::sleep(delay).await;
    assert_eq!(messages2.load(Ordering::SeqCst), 1);

    let connected_peers1 = network1.online_peers();
    assert_eq!(connected_peers1.online_peers.len(), 1);

    let connected_peers2 = network2.online_peers();
    assert_eq!(connected_peers2.online_peers.len(), 1);

    // Connecting to the same peer from network1
    network1
        .connect_peer(ConnectPeer {
            peer_id: peer2.clone(),
        })
        .await;
    tokio::time::sleep(delay).await;

    let connected_peers = network1.online_peers();
    assert_eq!(connected_peers.online_peers.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn multiple_networks() {
    let log_config = Configuration {
        max_log_level: Level::TRACE.into(),
        compact_mode: false,
        ..ConfigurationProxy::default()
            .build()
            .expect("Default logger config should always build")
    };
    // Can't use logger because it's failed to initialize.
    #[allow(clippy::print_stderr)]
    if let Err(err) = iroha_logger::init(&log_config) {
        eprintln!("Failed to initialize logger: {err}");
    }
    info!("Starting...");

    let delay = Duration::from_millis(200);

    let mut peers = Vec::new();
    for i in 0_u16..10_u16 {
        let addr = gen_address_with_port(12_015 + (i * 5));
        peers.push(addr);
    }

    let mut networks = Vec::new();
    let mut peer_ids = Vec::new();
    let msgs = Arc::new(AtomicU32::new(0));
    peers
        .iter()
        .map(|addr| start_network(addr.clone(), peers.clone(), Arc::clone(&msgs)))
        .collect::<FuturesUnordered<_>>()
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .for_each(|(address, handle, public_key)| {
            networks.push(handle);
            let peer_id = PeerId {
                address,
                public_key,
            };
            peer_ids.push(peer_id);
        });

    tokio::time::sleep(delay * 3).await;

    info!("Sending posts...");
    for network in &networks {
        for id in &peer_ids {
            let post = Post {
                data: TestMessage(String::from("Some data to send to peer")),
                peer_id: id.clone(),
            };
            network.post(post).await;
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
) -> (String, NetworkHandle<TestMessage>, PublicKey) {
    info!(peer_addr = %addr, "Starting network");

    let keypair = KeyPair::generate().unwrap();
    // This actor will get the messages from other peers and increment the counter
    let actor = TestActor::start(messages);

    let mut network = NetworkHandle::start(addr.clone(), keypair.public_key().clone())
        .await
        .unwrap();
    network.subscribe_to_peers_messages(actor).await;
    // The most needed delay!!!
    let delay: u64 = rand::random();
    tokio::time::sleep(Duration::from_millis(250 + (delay % 500))).await;

    let mut conn_count = 0_usize;
    for p in &peers {
        if *p != addr {
            let peer_id = PeerId {
                address: p.clone(),
                public_key: keypair.public_key().clone(),
            };

            network.connect_peer(ConnectPeer { peer_id }).await;
            conn_count += 1_usize;
        }
    }
    tokio::time::timeout(Duration::from_millis(1000), async {
        let mut connections = network.wait_online_peers_update().await.online_peers.len();
        while conn_count != connections {
            info!(peer_addr = %addr, %connections);
            connections = network.wait_online_peers_update().await.online_peers.len();
        }
    })
    .await
    .expect("Failed to get all connections");

    info!(peer_addr = %addr, %conn_count, "Got all connections!");

    (addr, network, keypair.public_key().clone())
}

#[test]
fn test_encryption() {
    use iroha_crypto::ursa::encryption::symm::prelude::*;

    const TEST_KEY: [u8; 32] = [
        5, 87, 82, 183, 220, 57, 107, 49, 227, 4, 96, 231, 198, 88, 153, 11, 22, 65, 56, 45, 237,
        35, 231, 165, 122, 153, 14, 68, 13, 84, 5, 24,
    ];

    let encryptor = SymmetricEncryptor::<ChaCha20Poly1305>::new_with_key(TEST_KEY).unwrap();
    let message = b"Some ciphertext";
    let aad = b"Iroha2 AAD";
    let res = encryptor.encrypt_easy(aad.as_ref(), message.as_ref());
    assert!(res.is_ok());

    let ciphertext = res.unwrap();
    let res_cipher = encryptor.decrypt_easy(aad.as_ref(), ciphertext.as_slice());
    assert!(res_cipher.is_ok());
    assert_eq!(res_cipher.unwrap().as_slice(), message);
}
