use std::{
    collections::HashSet,
    fmt::Debug,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
};

use futures::{prelude::*, stream::FuturesUnordered, task::AtomicWaker};
use iroha_config::parameters::actual::Network as Config;
use iroha_config_base::WithOrigin;
use iroha_crypto::KeyPair;
use iroha_data_model::prelude::PeerId;
use iroha_logger::{prelude::*, test_logger};
use iroha_p2p::{network::message::*, NetworkHandle};
use iroha_primitives::addr::socket_addr;
use parity_scale_codec::{Decode, Encode};
use tokio::{
    sync::{mpsc, Barrier},
    time::Duration,
};

#[derive(Clone, Debug, Decode, Encode)]
struct TestMessage(String);

fn setup_logger() {
    test_logger();
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
    let address = socket_addr!(127.0.0.1:12_000);
    let key_pair = KeyPair::random();
    let public_key = key_pair.public_key().clone();
    let idle_timeout = Duration::from_secs(60);
    let config = Config {
        address: WithOrigin::inline(address.clone()),
        idle_timeout,
    };
    let (network, _) = NetworkHandle::start(key_pair, config).await.unwrap();
    tokio::time::sleep(delay).await;

    info!("Connecting to peer...");
    let peer1 = PeerId::new(address.clone(), public_key.clone());
    let topology = HashSet::from([peer1.clone()]);
    network.update_topology(UpdateTopology(topology));
    tokio::time::sleep(delay).await;

    info!("Posting message...");
    network.post(Post {
        data: TestMessage("Some data to send to peer".to_owned()),
        peer_id: peer1,
    });

    tokio::time::sleep(delay).await;
}

#[derive(Clone, Debug)]
struct WaitForN(Arc<Inner>);

#[derive(Debug)]
struct Inner {
    counter: AtomicU32,
    n: u32,
    waker: AtomicWaker,
}

impl WaitForN {
    fn new(n: u32) -> Self {
        Self(Arc::new(Inner {
            counter: AtomicU32::new(0),
            n,
            waker: AtomicWaker::new(),
        }))
    }

    fn inc(&self) {
        self.0.counter.fetch_add(1, Ordering::Relaxed);
        self.0.waker.wake();
    }

    fn current(&self) -> u32 {
        self.0.counter.load(Ordering::Relaxed)
    }
}

impl Future for WaitForN {
    type Output = ();

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        // Check if condition is already satisfied
        if self.0.counter.load(Ordering::Relaxed) >= self.0.n {
            return std::task::Poll::Ready(());
        }

        self.0.waker.register(cx.waker());

        if self.0.counter.load(Ordering::Relaxed) >= self.0.n {
            return std::task::Poll::Ready(());
        }

        std::task::Poll::Pending
    }
}

#[derive(Debug)]
pub struct TestActor {
    messages: WaitForN,
    receiver: mpsc::Receiver<TestMessage>,
}

impl TestActor {
    fn start(messages: WaitForN) -> mpsc::Sender<TestMessage> {
        let (sender, receiver) = mpsc::channel(10);
        let mut test_actor = Self { messages, receiver };
        tokio::task::spawn(async move {
            loop {
                tokio::select! {
                    Some(msg) = test_actor.receiver.recv() => {
                        info!(?msg, "Actor received message");
                        test_actor.messages.inc();
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
    let delay = Duration::from_millis(300);
    let idle_timeout = Duration::from_secs(60);
    setup_logger();
    let key_pair1 = KeyPair::random();
    let public_key1 = key_pair1.public_key().clone();
    let key_pair2 = KeyPair::random().clone();
    let public_key2 = key_pair2.public_key().clone();
    info!("Starting first network...");
    let address1 = socket_addr!(127.0.0.1:12_005);
    let config1 = Config {
        address: WithOrigin::inline(address1.clone()),
        idle_timeout,
    };
    let (mut network1, _) = NetworkHandle::start(key_pair1, config1).await.unwrap();

    info!("Starting second network...");
    let address2 = socket_addr!(127.0.0.1:12_010);
    let config2 = Config {
        address: WithOrigin::inline(address2.clone()),
        idle_timeout,
    };
    let (network2, _) = NetworkHandle::start(key_pair2, config2).await.unwrap();

    let mut messages2 = WaitForN::new(1);
    let actor2 = TestActor::start(messages2.clone());
    network2.subscribe_to_peers_messages(actor2);

    info!("Connecting peers...");
    let peer1 = PeerId::new(address1.clone(), public_key1);
    let peer2 = PeerId::new(address2.clone(), public_key2);
    let topology1 = HashSet::from([peer2.clone()]);
    let topology2 = HashSet::from([peer1.clone()]);
    // Connect peers with each other
    network1.update_topology(UpdateTopology(topology1.clone()));
    network2.update_topology(UpdateTopology(topology2));

    tokio::time::timeout(Duration::from_millis(2000), async {
        let mut connections = network1.wait_online_peers_update(HashSet::len).await;
        while connections != 1 {
            connections = network1.wait_online_peers_update(HashSet::len).await;
        }
    })
    .await
    .expect("Failed to get all connections");

    info!("Posting message...");
    network1.post(Post {
        data: TestMessage("Some data to send to peer".to_owned()),
        peer_id: peer2,
    });

    tokio::time::timeout(delay, &mut messages2)
        .await
        .unwrap_or_else(|_| {
            panic!(
                "Failed to get all messages in given time (received {} out of 1)",
                messages2.current()
            )
        });

    let connected_peers1 = network1.online_peers(HashSet::len);
    assert_eq!(connected_peers1, 1);

    let connected_peers2 = network2.online_peers(HashSet::len);
    assert_eq!(connected_peers2, 1);

    // Connecting to the same peer from network1
    network1.update_topology(UpdateTopology(topology1));
    tokio::time::sleep(delay).await;

    let connected_peers = network1.online_peers(HashSet::len);
    assert_eq!(connected_peers, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn multiple_networks() {
    setup_logger();
    info!("Starting...");

    let mut peers = Vec::new();
    let mut key_pairs = Vec::new();
    for i in 0_u16..10_u16 {
        let address = socket_addr!(127.0.0.1: 12_015 + ( i * 5));
        let key_pair = KeyPair::random();
        let public_key = key_pair.public_key().clone();
        peers.push(PeerId::new(address, public_key));
        key_pairs.push(key_pair);
    }

    let mut networks = Vec::new();
    let mut peer_ids = Vec::new();
    let expected_msgs = (peers.len() * (peers.len() - 1))
        .try_into()
        .expect("Failed to convert to u32");
    let mut msgs = WaitForN::new(expected_msgs);
    let barrier = Arc::new(Barrier::new(peers.len()));
    peers
        .iter()
        .zip(key_pairs)
        .map(|(peer, key_pair)| {
            start_network(
                peer.clone(),
                key_pair,
                peers.clone(),
                msgs.clone(),
                Arc::clone(&barrier),
            )
        })
        .collect::<FuturesUnordered<_>>()
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .for_each(|(peer_id, handle)| {
            networks.push(handle);
            peer_ids.push(peer_id);
        });

    info!("Sending posts...");
    for network in &networks {
        for id in &peer_ids {
            let post = Post {
                data: TestMessage(String::from("Some data to send to peer")),
                peer_id: id.clone(),
            };
            network.post(post);
        }
    }
    info!("Posts sent");
    let timeout = Duration::from_millis(10_000);
    tokio::time::timeout(timeout, &mut msgs)
        .await
        .unwrap_or_else(|_| {
            panic!(
                "Failed to get all messages in given time {}ms (received {} out of {})",
                timeout.as_millis(),
                msgs.current(),
                expected_msgs,
            )
        });
}

async fn start_network(
    peer: PeerId,
    key_pair: KeyPair,
    peers: Vec<PeerId>,
    messages: WaitForN,
    barrier: Arc<Barrier>,
) -> (PeerId, NetworkHandle<TestMessage>) {
    info!(peer_addr = %peer.address, "Starting network");

    // This actor will get the messages from other peers and increment the counter
    let actor = TestActor::start(messages);

    let PeerId { address, .. } = peer.clone();
    let idle_timeout = Duration::from_secs(60);
    let config = Config {
        address: WithOrigin::inline(address),
        idle_timeout,
    };
    let (mut network, _) = NetworkHandle::start(key_pair, config).await.unwrap();
    network.subscribe_to_peers_messages(actor);

    let _ = barrier.wait().await;
    let topology = peers
        .into_iter()
        .filter(|p| p != &peer)
        .collect::<HashSet<_>>();
    let conn_count = topology.len();
    network.update_topology(UpdateTopology(topology));

    let _ = barrier.wait().await;
    tokio::time::timeout(Duration::from_millis(10_000), async {
        let mut connections = network.wait_online_peers_update(HashSet::len).await;
        while conn_count != connections {
            info!(peer_addr = %peer.address, %connections);
            connections = network.wait_online_peers_update(HashSet::len).await;
        }
    })
    .await
    .expect("Failed to get all connections");

    info!(peer_addr = %peer.address, %conn_count, "Got all connections!");

    (peer, network)
}

#[test]
fn test_encryption() {
    use iroha_crypto::encryption::{ChaCha20Poly1305, SymmetricEncryptor};

    const TEST_KEY: [u8; 32] = [
        5, 87, 82, 183, 220, 57, 107, 49, 227, 4, 96, 231, 198, 88, 153, 11, 22, 65, 56, 45, 237,
        35, 231, 165, 122, 153, 14, 68, 13, 84, 5, 24,
    ];

    let encryptor = SymmetricEncryptor::<ChaCha20Poly1305>::new_with_key(TEST_KEY);
    let message = b"Some ciphertext";
    let aad = b"Iroha2 AAD";
    let ciphertext = encryptor
        .encrypt_easy(aad.as_ref(), message.as_ref())
        .unwrap();
    let decrypted = encryptor
        .decrypt_easy(aad.as_ref(), ciphertext.as_slice())
        .unwrap();
    assert_eq!(decrypted.as_slice(), message);
}
