//! Endpoint policy, bounded tip recovery and concurrent native-read scheduling.

use super::*;
use iroha::config::Config;
use iroha_crypto::{Hash, HashOf, KeyPair};
use std::sync::{
    Arc, Barrier,
    atomic::{AtomicUsize, Ordering},
};

fn peer(seed: u8) -> PeerId {
    PeerId::new(
        KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal)
            .public_key()
            .clone(),
    )
}

fn client(network_id: NetworkId, endpoint: &str) -> Client {
    let key = KeyPair::from_seed(vec![83; 32], Algorithm::Ed25519);
    let table = toml::toml! {
        chain = "http-finality"
        network_id = (network_id.to_string())
        torii_url = endpoint
        [account]
        chain_discriminant = 753
        public_key = (key.public_key().to_string())
        private_key = (iroha_crypto::ExposedPrivateKey(key.private_key().clone()).to_string())
    };
    Client::builder(Config::load_table("http-tests.toml", table).unwrap())
        .build()
        .unwrap()
}

#[test]
fn endpoint_policy_only_allows_https_or_numeric_loopback() {
    for endpoint in [
        "https://parent.example/",
        "https://parent.example/peer/2/",
        "http://127.0.0.1:18080/",
        "http://[::1]:18080/",
    ] {
        validate_endpoint(&endpoint.parse().unwrap()).unwrap();
    }
    for endpoint in [
        "http://parent.example/",
        "http://localhost/",
        "https://secret@parent.example/",
        "https://parent.example/?secret=value",
        "https://parent.example/#fragment",
        "https://parent.example/no-slash",
        "ftp://parent.example/",
    ] {
        assert!(validate_endpoint(&endpoint.parse().unwrap()).is_err());
    }
}

#[test]
fn constructor_binds_network_and_distinct_bls_peers_without_dispatch() {
    let native = iroha_data_model::testing::native_finality::NativeFinalityFixture::start(
        "http-scope-fixture",
    );
    let root_scope = native.root_scope();
    let network = native.network_id();
    let proof = client(network, "https://parent.example/");
    let peers = vec![(peer(21), proof.clone()), (peer(22), proof.clone())];
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut source = HttpFinalitySource::new(
        network,
        NonZeroU64::new(2).unwrap(),
        vec![proof.clone()],
        peers.clone(),
        deadline,
        root_scope,
    )
    .unwrap();
    assert_eq!(source.root_scope, root_scope);
    assert_eq!(
        source.latest_attestation(&peer(23), &[1; 32]).unwrap_err(),
        HttpFinalityError::MissingPeer
    );
    assert_eq!(
        source.latest_attestation(&peer(21), &[0; 32]).unwrap_err(),
        HttpFinalityError::Invalid("zero challenge")
    );
    assert!(source.latest_attestations(&[], &[1; 32]).is_empty());
    source.deadline = Instant::now();
    assert_eq!(
        source
            .finality_proof(NonZeroU64::new(2).unwrap())
            .unwrap_err(),
        HttpFinalityError::Deadline
    );
    for (proofs, peers) in [
        (vec![], peers.clone()),
        (vec![proof.clone()], vec![]),
        (
            vec![proof.clone()],
            vec![peers[0].clone(), peers[0].clone()],
        ),
        (
            vec![proof.clone()],
            vec![(
                PeerId::new(
                    KeyPair::from_seed(vec![1; 32], Algorithm::Ed25519)
                        .public_key()
                        .clone(),
                ),
                proof.clone(),
            )],
        ),
        (
            vec![proof.clone()],
            vec![(
                peer(21),
                client(
                    NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
                        b"foreign",
                    ))),
                    "https://parent.example/",
                ),
            )],
        ),
        (
            vec![client(network, "http://parent.example/")],
            peers.clone(),
        ),
        (
            vec![proof.clone(); MAX_OBSERVATION_PEERS + 1],
            peers.clone(),
        ),
    ] {
        assert!(
            HttpFinalitySource::new(
                network,
                NonZeroU64::new(2).unwrap(),
                proofs,
                peers,
                deadline,
                root_scope
            )
            .is_err()
        );
    }
    assert!(
        HttpFinalitySource::new(
            network,
            NonZeroU64::new(2).unwrap(),
            vec![proof],
            peers,
            Instant::now(),
            root_scope
        )
        .is_err()
    );
}

#[test]
fn only_typed_progress_retries_and_every_attempt_shares_one_deadline() {
    let start = NonZeroU64::new(2).unwrap();
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut heights = vec![];
    let result = read_tip(start, deadline, |height| {
        heights.push(height.get());
        if height.get() == 2 {
            Err(TipRead::Progress(8))
        } else {
            Ok(8)
        }
    })
    .unwrap();
    assert_eq!(result, 8);
    assert_eq!(heights, [2, 8]);
    let mut calls = 0;
    assert_eq!(
        read_tip::<()>(start, deadline, |_| {
            calls += 1;
            Err(TipRead::Failed)
        }),
        Err(HttpFinalityError::Read)
    );
    assert_eq!(calls, 1);
    assert_eq!(
        read_tip::<()>(start, deadline, |_| Err(TipRead::Progress(0))),
        Err(HttpFinalityError::Read)
    );
    calls = 0;
    assert_eq!(
        read_tip::<()>(start, deadline, |height| {
            calls += 1;
            Err(TipRead::Progress(height.get() + 1))
        }),
        Err(HttpFinalityError::MovingTip)
    );
    assert_eq!(calls, MAX_TIP_ATTEMPTS);
    assert_eq!(
        read_tip::<()>(start, Instant::now(), |_| panic!(
            "elapsed reads cannot dispatch"
        )),
        Err(HttpFinalityError::Deadline)
    );
    let expired = Instant::now() + Duration::from_millis(5);
    assert_eq!(
        read_tip(start, expired, |_| {
            std::thread::sleep(Duration::from_millis(10));
            Ok(())
        }),
        Err(HttpFinalityError::Deadline)
    );
}

#[test]
fn concurrent_reads_overlap_peers_preserve_order_and_join_before_returning() {
    let barrier = Arc::new(Barrier::new(MAX_CONCURRENT_PEERS));
    let finished = AtomicUsize::new(0);
    let values = (0..MAX_CONCURRENT_PEERS).collect::<Vec<_>>();
    let results = concurrent_reads(&values, |value| {
        barrier.wait();
        finished.fetch_add(1, Ordering::SeqCst);
        Ok(*value)
    });
    assert_eq!(
        results,
        values.iter().map(|value| Ok(*value)).collect::<Vec<_>>()
    );
    assert_eq!(finished.load(Ordering::SeqCst), values.len());
    assert_eq!(
        concurrent_reads(&[1, 2, 3], |value| if *value == 2 {
            Err(HttpFinalityError::Read)
        } else {
            Ok(*value)
        }),
        vec![Ok(1), Err(HttpFinalityError::Read), Ok(3)]
    );
    assert_eq!(
        concurrent_reads(&[1], |_| -> Result<(), HttpFinalityError> {
            panic!("joined worker failure")
        }),
        vec![Err(HttpFinalityError::Worker)]
    );
}
