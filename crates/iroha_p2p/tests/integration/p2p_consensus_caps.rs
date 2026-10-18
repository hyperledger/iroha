//! Handshake caps (consensus) tests: accept match, reject mismatch.
#![allow(
    clippy::clone_on_copy,
    clippy::redundant_closure_for_method_calls,
    clippy::too_many_lines
)]
use iroha_config::parameters::actual::Network as Config;
use iroha_config::parameters::defaults::network::TRUST_GOSSIP;
use iroha_data_model::block::consensus::ConsensusMode;
use iroha_futures::supervisor::ShutdownSignal;
use iroha_model_base::peer::PeerId;
use iroha_p2p::{
    ConfidentialFeatureDigest, ConfidentialHandshakeCaps, ConsensusConfigCaps,
    ConsensusHandshakeCaps, CryptoHandshakeCaps, NetworkHandle, network::message::*,
};
use norito::codec::{Decode, Encode};
use std::{collections::HashSet, num::NonZeroUsize};
use tokio::time::Duration;
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_p2p::tests::integration::p2p_consensus_caps::Dummy")]
#[derive(Clone, Debug, Decode, Encode)]
struct Dummy;
impl ClassifyTopic for Dummy {
    fn inbound_topic(payload: &[u8], flags: u8) -> Result<Option<Topic>, norito::core::Error> {
        norito::core::validate_header_flags(flags)?;
        // Bound the unit-struct probe before decoding it.
        if payload.len() > 8 {
            return Err(norito::core::Error::LengthMismatch);
        }
        let _flags = norito::core::DecodeFlagsGuard::enter(flags);
        let (value, used) = norito::core::decode_field_canonical::<Self>(payload)?;
        if used != payload.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        Ok(Some(value.topic()))
    }
}
impl<'a> norito::core::DecodeFromSlice<'a> for Dummy {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        norito::core::decode_field_canonical::<Self>(bytes)
    }
}
fn sample_consensus_config_caps() -> ConsensusConfigCaps {
    ConsensusConfigCaps {
        execution_policy_hash: [0xB4; 32],
        nexus_policy_digest: [0xA5; 32],
        native_config_fingerprint: [0xC3; 32],
        ivm_gas_schedule_hash: [0xE7; 32],
    }
}
#[test]
fn consensus_config_caps_wire_roundtrip_preserves_admission_digests() {
    let expected = sample_consensus_config_caps();
    let encoded = expected.encode();
    let mut cursor = encoded.as_slice();
    let decoded = ConsensusConfigCaps::decode(&mut cursor).expect("decode consensus config caps");
    assert!(
        cursor.is_empty(),
        "decoder must consume the complete caps wire payload"
    );
    assert_eq!(decoded, expected);
    assert_eq!(decoded.execution_policy_hash, [0xB4; 32]);
    assert_eq!(decoded.nexus_policy_digest, [0xA5; 32]);
    assert_eq!(decoded.native_config_fingerprint, [0xC3; 32]);
    assert_eq!(decoded.ivm_gas_schedule_hash, [0xE7; 32]);
}
fn cfg(addr: iroha_primitives::addr::SocketAddr) -> Config {
    // Keep admission inexpensive so these tests continue to measure consensus
    // capability matching. `test_network_config` isolates replay state.
    let soranet_handshake = super::low_cost_test_soranet_handshake();
    Config {
        happy_eyeballs_stagger: Duration::from_millis(10),
        p2p_queue_cap_high: NonZeroUsize::new(128).unwrap(),
        p2p_queue_cap_low: NonZeroUsize::new(128).unwrap(),
        p2p_post_queue_cap: NonZeroUsize::new(64).unwrap(),
        // These capability-only pairs need at most two live connection tenures
        // during replacement. Bound the fixture to four connections instead of
        // inheriting the 97-connection Core profile with only 128 actor ranks.
        // This reduces source ownership; no queue or byte ceiling is increased.
        max_total_connections: NonZeroUsize::new(4),
        ..super::test_network_config(
            addr.clone(),
            addr,
            Duration::from_millis(1000),
            soranet_handshake,
            TRUST_GOSSIP,
        )
    }
}
const MATCH_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MISMATCH_OBSERVATION: Duration = Duration::from_secs(1);
async fn assert_peer_connects(network: &NetworkHandle<Dummy>, expected: &PeerId) {
    let mut online = network.online_peers_receiver();
    tokio::time::timeout(
        MATCH_CONNECT_TIMEOUT,
        online.wait_for(|peers| peers.iter().any(|peer| peer.id() == expected)),
    )
    .await
    .expect("matching peer did not connect before the deadline")
    .expect("online peers channel closed while waiting for a matching peer");
}
async fn assert_peer_stays_offline(network: &NetworkHandle<Dummy>, forbidden: &PeerId) {
    let mut online = network.online_peers_receiver();
    match tokio::time::timeout(
        MISMATCH_OBSERVATION,
        online.wait_for(|peers| peers.iter().any(|peer| peer.id() == forbidden)),
    )
    .await
    {
        Err(_) => {}
        Ok(Ok(_)) => panic!("mismatched peer entered the online set"),
        Ok(Err(error)) => panic!("online peers channel closed unexpectedly: {error}"),
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zero_delay_initial_trusted_sources_precede_authenticated_handshake() {
    let chain = super::test_network_id("initial-source-authority-test");
    let kp1 = super::random_node_key_pair();
    let kp2 = super::random_node_key_pair();
    let id1 = PeerId::from(kp1.public_key().clone());
    let id2 = PeerId::from(kp2.public_key().clone());
    let addr1 = super::next_addr();
    let addr2 = super::next_addr();
    let mut cfg1 = cfg(addr1.clone());
    let mut cfg2 = cfg(addr2.clone());
    cfg1.connect_startup_delay = Duration::ZERO;
    cfg2.connect_startup_delay = Duration::ZERO;
    cfg1.max_total_connections = NonZeroUsize::new(1);
    cfg2.max_total_connections = NonZeroUsize::new(1);
    let (net1, _child1) = match Box::pin(
        NetworkHandle::<Dummy>::start_with_crypto_and_initial_trusted_sources(
            super::p2p_identity_keys(kp1),
            cfg1,
            chain.clone(),
            iroha_p2p::network::HandshakeCapabilities {
                consensus: None,
                confidential: None,
                crypto: None,
            },
            HashSet::from([id2.clone()]),
            ShutdownSignal::new(),
        ),
    )
    .await
    {
        Ok(started) => started,
        Err(error) => panic!("capability fixture failed before its required assertion: {error:?}"),
    };
    let (net2, _child2) = match Box::pin(
        NetworkHandle::<Dummy>::start_with_crypto_and_initial_trusted_sources(
            super::p2p_identity_keys(kp2),
            cfg2,
            chain,
            iroha_p2p::network::HandshakeCapabilities {
                consensus: None,
                confidential: None,
                crypto: None,
            },
            HashSet::from([id1.clone()]),
            ShutdownSignal::new(),
        ),
    )
    .await
    {
        Ok(started) => started,
        Err(error) => panic!("capability fixture failed before its required assertion: {error:?}"),
    };
    net2.update_topology(UpdateTopology(HashSet::from([id1.clone()])));
    // Deliberately publish no asynchronous trusted-peer update: source
    // authority must already exist when the zero-delay connection authenticates.
    net1.update_topology(UpdateTopology(HashSet::from([id2.clone()])));
    net1.update_peers_addresses(UpdatePeers(vec![(id2.clone(), addr2)]));
    assert_peer_connects(&net1, &id2).await;
    assert_peer_connects(&net2, &id1).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn consensus_caps_match_connects() {
    let chain = super::test_network_id("caps-test");
    let kp1 = super::random_node_key_pair();
    let kp2 = super::random_node_key_pair();
    let addr1 = super::next_addr();
    let addr2 = super::next_addr();
    let config_caps = sample_consensus_config_caps();
    let caps = ConsensusHandshakeCaps {
        mode: ConsensusMode::Permissioned,
        proto_version: 2,
        consensus_fingerprint: [1u8; 32],
        config: config_caps.clone(),
    };
    let (net1, _ch1) = match NetworkHandle::<Dummy>::start(
        super::p2p_identity_keys(kp1.clone()),
        cfg(addr1.clone()),
        chain.clone(),
        Some(caps.clone()),
        None,
        ShutdownSignal::new(),
    )
    .await
    {
        Ok(ok) => ok,
        Err(error) => panic!("capability fixture must start: {error:?}"),
    };
    let (net2, _ch2) = match NetworkHandle::<Dummy>::start(
        super::p2p_identity_keys(kp2.clone()),
        cfg(addr2.clone()),
        chain.clone(),
        Some(caps.clone()),
        None,
        ShutdownSignal::new(),
    )
    .await
    {
        Ok(ok) => ok,
        Err(error) => panic!("capability fixture must start: {error:?}"),
    };
    let p2 = iroha_data_model::peer::Peer::new(addr2.clone(), kp2.public_key().clone());
    // Authorize the actual dialer independently of the capability under test.
    net2.update_topology(UpdateTopology(HashSet::from([PeerId::from(
        kp1.public_key().clone(),
    )])));
    net1.update_topology(UpdateTopology([p2.id().clone()].into_iter().collect()));
    net1.update_peers_addresses(UpdatePeers(vec![(p2.id().clone(), addr2.clone())]));
    assert_peer_connects(&net1, p2.id()).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn consensus_caps_mismatch_rejected() {
    let chain = super::test_network_id("caps-test");
    let kp1 = super::random_node_key_pair();
    let kp2 = super::random_node_key_pair();
    let addr1 = super::next_addr();
    let addr2 = super::next_addr();
    let config_caps = sample_consensus_config_caps();
    let caps_ok = ConsensusHandshakeCaps {
        mode: ConsensusMode::Permissioned,
        proto_version: 2,
        consensus_fingerprint: [2u8; 32],
        config: config_caps.clone(),
    };
    let caps_bad = ConsensusHandshakeCaps {
        mode: ConsensusMode::Npos, // mismatch
        proto_version: 2,
        consensus_fingerprint: [2u8; 32],
        config: config_caps,
    };
    let (net1, _ch1) = match NetworkHandle::<Dummy>::start(
        super::p2p_identity_keys(kp1.clone()),
        cfg(addr1.clone()),
        chain.clone(),
        Some(caps_ok.clone()),
        None,
        ShutdownSignal::new(),
    )
    .await
    {
        Ok(ok) => ok,
        Err(error) => panic!("capability fixture must start: {error:?}"),
    };
    let (net2, _ch2) = match NetworkHandle::<Dummy>::start(
        super::p2p_identity_keys(kp2.clone()),
        cfg(addr2.clone()),
        chain.clone(),
        Some(caps_bad.clone()),
        None,
        ShutdownSignal::new(),
    )
    .await
    {
        Ok(ok) => ok,
        Err(error) => panic!("capability fixture must start: {error:?}"),
    };
    let p2 = iroha_data_model::peer::Peer::new(addr2.clone(), kp2.public_key().clone());
    // Authorize the actual dialer independently of the capability under test.
    net2.update_topology(UpdateTopology(HashSet::from([PeerId::from(
        kp1.public_key().clone(),
    )])));
    net1.update_topology(UpdateTopology([p2.id().clone()].into_iter().collect()));
    net1.update_peers_addresses(UpdatePeers(vec![(p2.id().clone(), addr2.clone())]));
    assert_peer_stays_offline(&net1, p2.id()).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn consensus_config_caps_mismatch_rejected() {
    let chain = super::test_network_id("caps-config-test");
    let kp1 = super::random_node_key_pair();
    let kp2 = super::random_node_key_pair();
    let addr1 = super::next_addr();
    let addr2 = super::next_addr();
    let config_caps = sample_consensus_config_caps();
    let mut mismatched = config_caps.clone();
    mismatched.native_config_fingerprint = [0xD4; 32];
    let caps_ok = ConsensusHandshakeCaps {
        mode: ConsensusMode::Permissioned,
        proto_version: 2,
        consensus_fingerprint: [3u8; 32],
        config: config_caps,
    };
    let caps_bad = ConsensusHandshakeCaps {
        mode: ConsensusMode::Permissioned,
        proto_version: 2,
        consensus_fingerprint: [3u8; 32],
        config: mismatched,
    };
    let (net1, _ch1) = match NetworkHandle::<Dummy>::start(
        super::p2p_identity_keys(kp1.clone()),
        cfg(addr1.clone()),
        chain.clone(),
        Some(caps_ok.clone()),
        None,
        ShutdownSignal::new(),
    )
    .await
    {
        Ok(ok) => ok,
        Err(error) => panic!("capability fixture must start: {error:?}"),
    };
    let (net2, _ch2) = match NetworkHandle::<Dummy>::start(
        super::p2p_identity_keys(kp2.clone()),
        cfg(addr2.clone()),
        chain.clone(),
        Some(caps_bad.clone()),
        None,
        ShutdownSignal::new(),
    )
    .await
    {
        Ok(ok) => ok,
        Err(error) => panic!("capability fixture must start: {error:?}"),
    };
    let p2 = iroha_data_model::peer::Peer::new(addr2.clone(), kp2.public_key().clone());
    // Authorize the actual dialer independently of the capability under test.
    net2.update_topology(UpdateTopology(HashSet::from([PeerId::from(
        kp1.public_key().clone(),
    )])));
    net1.update_topology(UpdateTopology([p2.id().clone()].into_iter().collect()));
    net1.update_peers_addresses(UpdatePeers(vec![(p2.id().clone(), addr2.clone())]));
    assert_peer_stays_offline(&net1, p2.id()).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn confidential_caps_match_connects() {
    let chain = super::test_network_id("conf-caps-test");
    let kp1 = super::random_node_key_pair();
    let kp2 = super::random_node_key_pair();
    let addr1 = super::next_addr();
    let addr2 = super::next_addr();
    let features = Some(ConfidentialFeatureDigest {
        vk_set_hash: Some([7u8; 32]),
        poseidon_params_id: Some(11),
        pedersen_params_id: Some(22),
        conf_rules_version: Some(1),
        zk_policy_hash: Some([31u8; 32]),
    });
    let caps = ConfidentialHandshakeCaps {
        enabled: true,
        assume_valid: false,
        verifier_backend: "halo2-ipa-pallas".to_string(),
        features: features.clone(),
    };
    let (net1, _ch1) = match NetworkHandle::<Dummy>::start(
        super::p2p_identity_keys(kp1.clone()),
        cfg(addr1.clone()),
        chain.clone(),
        None,
        Some(caps.clone()),
        ShutdownSignal::new(),
    )
    .await
    {
        Ok(ok) => ok,
        Err(error) => panic!("capability fixture must start: {error:?}"),
    };
    let (net2, _ch2) = match NetworkHandle::<Dummy>::start(
        super::p2p_identity_keys(kp2.clone()),
        cfg(addr2.clone()),
        chain.clone(),
        None,
        Some(caps.clone()),
        ShutdownSignal::new(),
    )
    .await
    {
        Ok(ok) => ok,
        Err(error) => panic!("capability fixture must start: {error:?}"),
    };
    let p2 = iroha_data_model::peer::Peer::new(addr2.clone(), kp2.public_key().clone());
    // Authorize the actual dialer independently of the capability under test.
    net2.update_topology(UpdateTopology(HashSet::from([PeerId::from(
        kp1.public_key().clone(),
    )])));
    net1.update_topology(UpdateTopology([p2.id().clone()].into_iter().collect()));
    net1.update_peers_addresses(UpdatePeers(vec![(p2.id().clone(), addr2.clone())]));
    assert_peer_connects(&net1, p2.id()).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn confidential_caps_mismatch_rejected() {
    let chain = super::test_network_id("conf-caps-test");
    let kp1 = super::random_node_key_pair();
    let kp2 = super::random_node_key_pair();
    let addr1 = super::next_addr();
    let addr2 = super::next_addr();
    let features = Some(ConfidentialFeatureDigest {
        vk_set_hash: Some([9u8; 32]),
        poseidon_params_id: Some(13),
        pedersen_params_id: Some(26),
        conf_rules_version: Some(1),
        zk_policy_hash: Some([32u8; 32]),
    });
    let caps_ok = ConfidentialHandshakeCaps {
        enabled: true,
        assume_valid: false,
        verifier_backend: "halo2-ipa-pallas".to_string(),
        features: features.clone(),
    };
    let caps_bad = ConfidentialHandshakeCaps {
        enabled: true,
        assume_valid: true, // observers allowed; should mismatch validators
        verifier_backend: "halo2-ipa-pallas".to_string(),
        features,
    };
    let (net1, _ch1) = match NetworkHandle::<Dummy>::start(
        super::p2p_identity_keys(kp1.clone()),
        cfg(addr1.clone()),
        chain.clone(),
        None,
        Some(caps_ok.clone()),
        ShutdownSignal::new(),
    )
    .await
    {
        Ok(ok) => ok,
        Err(error) => panic!("capability fixture must start: {error:?}"),
    };
    let (net2, _ch2) = match NetworkHandle::<Dummy>::start(
        super::p2p_identity_keys(kp2.clone()),
        cfg(addr2.clone()),
        chain.clone(),
        None,
        Some(caps_bad.clone()),
        ShutdownSignal::new(),
    )
    .await
    {
        Ok(ok) => ok,
        Err(error) => panic!("capability fixture must start: {error:?}"),
    };
    let p2 = iroha_data_model::peer::Peer::new(addr2.clone(), kp2.public_key().clone());
    // Authorize the actual dialer independently of the capability under test.
    net2.update_topology(UpdateTopology(HashSet::from([PeerId::from(
        kp1.public_key().clone(),
    )])));
    net1.update_topology(UpdateTopology([p2.id().clone()].into_iter().collect()));
    net1.update_peers_addresses(UpdatePeers(vec![(p2.id().clone(), addr2.clone())]));
    assert_peer_stays_offline(&net1, p2.id()).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn confidential_caps_backend_mismatch_rejected() {
    let chain = super::test_network_id("conf-caps-test");
    let kp1 = super::random_node_key_pair();
    let kp2 = super::random_node_key_pair();
    let addr1 = super::next_addr();
    let addr2 = super::next_addr();
    let features = Some(ConfidentialFeatureDigest {
        vk_set_hash: Some([3u8; 32]),
        poseidon_params_id: Some(5),
        pedersen_params_id: Some(8),
        conf_rules_version: Some(1),
        zk_policy_hash: Some([33u8; 32]),
    });
    let caps_ok = ConfidentialHandshakeCaps {
        enabled: true,
        assume_valid: false,
        verifier_backend: "halo2-ipa-pallas".to_string(),
        features: features.clone(),
    };
    let caps_bad = ConfidentialHandshakeCaps {
        enabled: true,
        assume_valid: false,
        verifier_backend: "halo2-ipa-goldilocks".to_string(),
        features,
    };
    let (net1, _ch1) = match NetworkHandle::<Dummy>::start(
        super::p2p_identity_keys(kp1.clone()),
        cfg(addr1.clone()),
        chain.clone(),
        None,
        Some(caps_ok.clone()),
        ShutdownSignal::new(),
    )
    .await
    {
        Ok(ok) => ok,
        Err(error) => panic!("capability fixture must start: {error:?}"),
    };
    let (net2, _ch2) = match NetworkHandle::<Dummy>::start(
        super::p2p_identity_keys(kp2.clone()),
        cfg(addr2.clone()),
        chain.clone(),
        None,
        Some(caps_bad.clone()),
        ShutdownSignal::new(),
    )
    .await
    {
        Ok(ok) => ok,
        Err(error) => panic!("capability fixture must start: {error:?}"),
    };
    let p2 = iroha_data_model::peer::Peer::new(addr2.clone(), kp2.public_key().clone());
    // Authorize the actual dialer independently of the capability under test.
    net2.update_topology(UpdateTopology(HashSet::from([PeerId::from(
        kp1.public_key().clone(),
    )])));
    net1.update_topology(UpdateTopology([p2.id().clone()].into_iter().collect()));
    net1.update_peers_addresses(UpdatePeers(vec![(p2.id().clone(), addr2.clone())]));
    assert_peer_stays_offline(&net1, p2.id()).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn confidential_caps_features_mismatch_rejected() {
    let chain = super::test_network_id("conf-caps-test");
    let kp1 = super::random_node_key_pair();
    let kp2 = super::random_node_key_pair();
    let addr1 = super::next_addr();
    let addr2 = super::next_addr();
    let features_ok = Some(ConfidentialFeatureDigest {
        vk_set_hash: Some([1u8; 32]),
        poseidon_params_id: Some(42),
        pedersen_params_id: Some(84),
        conf_rules_version: Some(1),
        zk_policy_hash: Some([34u8; 32]),
    });
    let features_bad = Some(ConfidentialFeatureDigest {
        vk_set_hash: Some([2u8; 32]), // mismatch
        poseidon_params_id: Some(42),
        pedersen_params_id: Some(84),
        conf_rules_version: Some(1),
        zk_policy_hash: Some([34u8; 32]),
    });
    let caps_ok = ConfidentialHandshakeCaps {
        enabled: true,
        assume_valid: false,
        verifier_backend: "halo2-ipa-pallas".to_string(),
        features: features_ok,
    };
    let caps_bad = ConfidentialHandshakeCaps {
        enabled: true,
        assume_valid: false,
        verifier_backend: "halo2-ipa-pallas".to_string(),
        features: features_bad,
    };
    let (net1, _ch1) = match NetworkHandle::<Dummy>::start(
        super::p2p_identity_keys(kp1.clone()),
        cfg(addr1.clone()),
        chain.clone(),
        None,
        Some(caps_ok.clone()),
        ShutdownSignal::new(),
    )
    .await
    {
        Ok(ok) => ok,
        Err(error) => panic!("capability fixture must start: {error:?}"),
    };
    let (net2, _ch2) = match NetworkHandle::<Dummy>::start(
        super::p2p_identity_keys(kp2.clone()),
        cfg(addr2.clone()),
        chain.clone(),
        None,
        Some(caps_bad.clone()),
        ShutdownSignal::new(),
    )
    .await
    {
        Ok(ok) => ok,
        Err(error) => panic!("capability fixture must start: {error:?}"),
    };
    let p2 = iroha_data_model::peer::Peer::new(addr2.clone(), kp2.public_key().clone());
    // Authorize the actual dialer independently of the capability under test.
    net2.update_topology(UpdateTopology(HashSet::from([PeerId::from(
        kp1.public_key().clone(),
    )])));
    net1.update_topology(UpdateTopology([p2.id().clone()].into_iter().collect()));
    net1.update_peers_addresses(UpdatePeers(vec![(p2.id().clone(), addr2.clone())]));
    assert_peer_stays_offline(&net1, p2.id()).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn confidential_caps_stale_digest_recovers_after_alignment() {
    let chain = super::test_network_id("conf-caps-recover-test");
    let validator_kp = super::random_node_key_pair();
    let peer_kp = super::random_node_key_pair();
    let addr1 = super::next_addr();
    let addr_stale = super::next_addr();
    let addr_fresh = super::next_addr();
    let features_expected = Some(ConfidentialFeatureDigest {
        vk_set_hash: Some([4u8; 32]),
        poseidon_params_id: Some(99),
        pedersen_params_id: Some(100),
        conf_rules_version: Some(1),
        zk_policy_hash: Some([35u8; 32]),
    });
    let features_stale = Some(ConfidentialFeatureDigest {
        vk_set_hash: Some([5u8; 32]), // stale digest
        poseidon_params_id: Some(99),
        pedersen_params_id: Some(100),
        conf_rules_version: Some(1),
        zk_policy_hash: Some([35u8; 32]),
    });
    let shutdown_validator = ShutdownSignal::new();
    let (net1, _child1) = match NetworkHandle::<Dummy>::start(
        super::p2p_identity_keys(validator_kp.clone()),
        cfg(addr1.clone()),
        chain.clone(),
        None,
        Some(ConfidentialHandshakeCaps {
            enabled: true,
            assume_valid: false,
            verifier_backend: "halo2-ipa-pallas".to_string(),
            features: features_expected.clone(),
        }),
        shutdown_validator.clone(),
    )
    .await
    {
        Ok(ok) => ok,
        Err(error) => panic!("capability fixture must start: {error:?}"),
    };
    let shutdown_stale = ShutdownSignal::new();
    let (net2_stale, _child2_stale) = match NetworkHandle::<Dummy>::start(
        super::p2p_identity_keys(peer_kp.clone()),
        cfg(addr_stale.clone()),
        chain.clone(),
        None,
        Some(ConfidentialHandshakeCaps {
            enabled: true,
            assume_valid: false,
            verifier_backend: "halo2-ipa-pallas".to_string(),
            features: features_stale,
        }),
        shutdown_stale.clone(),
    )
    .await
    {
        Ok(ok) => ok,
        Err(error) => {
            shutdown_validator.send();
            panic!("capability alignment fixture must start: {error:?}");
        }
    };
    net2_stale.update_topology(UpdateTopology(HashSet::from([PeerId::from(
        validator_kp.public_key().clone(),
    )])));
    let stale_peer =
        iroha_data_model::peer::Peer::new(addr_stale.clone(), peer_kp.public_key().clone());
    net1.update_topology(UpdateTopology(
        [stale_peer.id().clone()].into_iter().collect(),
    ));
    net1.update_peers_addresses(UpdatePeers(vec![(
        stale_peer.id().clone(),
        addr_stale.clone(),
    )]));
    tokio::time::sleep(Duration::from_millis(150)).await;
    let stale_online = net1.online_peers(|set| set.len());
    assert_eq!(
        stale_online, 0,
        "stale digest must keep peer out of rotation"
    );
    shutdown_stale.send();
    drop(net2_stale);
    let shutdown_fresh = ShutdownSignal::new();
    let (net2_fresh, _child2_fresh) = match NetworkHandle::<Dummy>::start(
        super::p2p_identity_keys(peer_kp.clone()),
        cfg(addr_fresh.clone()),
        chain.clone(),
        None,
        Some(ConfidentialHandshakeCaps {
            enabled: true,
            assume_valid: false,
            verifier_backend: "halo2-ipa-pallas".to_string(),
            features: features_expected.clone(),
        }),
        shutdown_fresh.clone(),
    )
    .await
    {
        Ok(ok) => ok,
        Err(error) => {
            shutdown_validator.send();
            panic!("capability alignment fixture must start: {error:?}");
        }
    };
    net2_fresh.update_topology(UpdateTopology(HashSet::from([PeerId::from(
        validator_kp.public_key().clone(),
    )])));
    let fresh_peer =
        iroha_data_model::peer::Peer::new(addr_fresh.clone(), peer_kp.public_key().clone());
    net1.update_topology(UpdateTopology(
        [fresh_peer.id().clone()].into_iter().collect(),
    ));
    net1.update_peers_addresses(UpdatePeers(vec![(
        fresh_peer.id().clone(),
        addr_fresh.clone(),
    )]));
    let target_peer = fresh_peer.clone();
    let net1_clone = net1.clone();
    let wait_result = tokio::time::timeout(Duration::from_millis(750), async move {
        loop {
            let online = net1_clone.online_peers(|set| set.clone());
            if online.contains(&target_peer) {
                break online.len();
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    shutdown_fresh.send();
    shutdown_validator.send();
    drop(net2_fresh);
    let count = match wait_result {
        Ok(count) => count,
        Err(error) => panic!("capability fixture failed before its required assertion: {error:?}"),
    };
    assert!(
        count >= 1,
        "aligned digest should allow the peer into rotation"
    );
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn crypto_caps_match_connects() {
    let chain = super::test_network_id("crypto-caps-test");
    let kp1 = super::random_node_key_pair();
    let kp2 = super::random_node_key_pair();
    let addr1 = super::next_addr();
    let addr2 = super::next_addr();
    let caps = CryptoHandshakeCaps {
        sm_enabled: true,
        sm_openssl_preview: false,
        require_sm_handshake_match: true,
        require_sm_openssl_preview_match: true,
    };
    let (net1, _ch1) = match Box::pin(NetworkHandle::<Dummy>::start_with_crypto(
        super::p2p_identity_keys(kp1.clone()),
        cfg(addr1.clone()),
        chain.clone(),
        iroha_p2p::network::HandshakeCapabilities {
            consensus: None,
            confidential: None,
            crypto: Some(caps.clone()),
        },
        ShutdownSignal::new(),
    ))
    .await
    {
        Ok(ok) => ok,
        Err(error) => panic!("capability fixture must start: {error:?}"),
    };
    let (net2, _ch2) = match Box::pin(NetworkHandle::<Dummy>::start_with_crypto(
        super::p2p_identity_keys(kp2.clone()),
        cfg(addr2.clone()),
        chain.clone(),
        iroha_p2p::network::HandshakeCapabilities {
            consensus: None,
            confidential: None,
            crypto: Some(caps.clone()),
        },
        ShutdownSignal::new(),
    ))
    .await
    {
        Ok(ok) => ok,
        Err(error) => panic!("capability fixture must start: {error:?}"),
    };
    let p2 = iroha_data_model::peer::Peer::new(addr2.clone(), kp2.public_key().clone());
    // Authorize the actual dialer independently of the capability under test.
    net2.update_topology(UpdateTopology(HashSet::from([PeerId::from(
        kp1.public_key().clone(),
    )])));
    net1.update_topology(UpdateTopology([p2.id().clone()].into_iter().collect()));
    net1.update_peers_addresses(UpdatePeers(vec![(p2.id().clone(), addr2.clone())]));
    assert_peer_connects(&net1, p2.id()).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn crypto_caps_mismatch_rejected() {
    let chain = super::test_network_id("crypto-caps-test");
    let kp1 = super::random_node_key_pair();
    let kp2 = super::random_node_key_pair();
    let addr1 = super::next_addr();
    let addr2 = super::next_addr();
    let caps_enabled = CryptoHandshakeCaps {
        sm_enabled: true,
        sm_openssl_preview: false,
        require_sm_handshake_match: true,
        require_sm_openssl_preview_match: true,
    };
    let caps_disabled = CryptoHandshakeCaps {
        sm_enabled: false,
        sm_openssl_preview: false,
        require_sm_handshake_match: true,
        require_sm_openssl_preview_match: true,
    };
    let (net1, _ch1) = match Box::pin(NetworkHandle::<Dummy>::start_with_crypto(
        super::p2p_identity_keys(kp1.clone()),
        cfg(addr1.clone()),
        chain.clone(),
        iroha_p2p::network::HandshakeCapabilities {
            consensus: None,
            confidential: None,
            crypto: Some(caps_enabled.clone()),
        },
        ShutdownSignal::new(),
    ))
    .await
    {
        Ok(ok) => ok,
        Err(error) => panic!("capability fixture must start: {error:?}"),
    };
    let (net2, _ch2) = match Box::pin(NetworkHandle::<Dummy>::start_with_crypto(
        super::p2p_identity_keys(kp2.clone()),
        cfg(addr2.clone()),
        chain.clone(),
        iroha_p2p::network::HandshakeCapabilities {
            consensus: None,
            confidential: None,
            crypto: Some(caps_disabled.clone()),
        },
        ShutdownSignal::new(),
    ))
    .await
    {
        Ok(ok) => ok,
        Err(error) => panic!("capability fixture must start: {error:?}"),
    };
    let p2 = iroha_data_model::peer::Peer::new(addr2.clone(), kp2.public_key().clone());
    // Authorize the actual dialer independently of the capability under test.
    net2.update_topology(UpdateTopology(HashSet::from([PeerId::from(
        kp1.public_key().clone(),
    )])));
    net1.update_topology(UpdateTopology([p2.id().clone()].into_iter().collect()));
    net1.update_peers_addresses(UpdatePeers(vec![(p2.id().clone(), addr2.clone())]));
    assert_peer_stays_offline(&net1, p2.id()).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn crypto_caps_mismatch_allowed_when_permissive() {
    let chain = super::test_network_id("crypto-caps-test");
    let kp1 = super::random_node_key_pair();
    let kp2 = super::random_node_key_pair();
    let addr1 = super::next_addr();
    let addr2 = super::next_addr();
    let caps_enabled = CryptoHandshakeCaps {
        sm_enabled: true,
        sm_openssl_preview: false,
        require_sm_handshake_match: false,
        require_sm_openssl_preview_match: false,
    };
    let caps_disabled = CryptoHandshakeCaps {
        sm_enabled: false,
        sm_openssl_preview: false,
        require_sm_handshake_match: false,
        require_sm_openssl_preview_match: false,
    };
    let (net1, _ch1) = match Box::pin(NetworkHandle::<Dummy>::start_with_crypto(
        super::p2p_identity_keys(kp1.clone()),
        cfg(addr1.clone()),
        chain.clone(),
        iroha_p2p::network::HandshakeCapabilities {
            consensus: None,
            confidential: None,
            crypto: Some(caps_enabled.clone()),
        },
        ShutdownSignal::new(),
    ))
    .await
    {
        Ok(ok) => ok,
        Err(error) => panic!("capability fixture must start: {error:?}"),
    };
    let (net2, _ch2) = match Box::pin(NetworkHandle::<Dummy>::start_with_crypto(
        super::p2p_identity_keys(kp2.clone()),
        cfg(addr2.clone()),
        chain.clone(),
        iroha_p2p::network::HandshakeCapabilities {
            consensus: None,
            confidential: None,
            crypto: Some(caps_disabled.clone()),
        },
        ShutdownSignal::new(),
    ))
    .await
    {
        Ok(ok) => ok,
        Err(error) => panic!("capability fixture must start: {error:?}"),
    };
    let p2 = iroha_data_model::peer::Peer::new(addr2.clone(), kp2.public_key().clone());
    // Authorize the actual dialer independently of the capability under test.
    net2.update_topology(UpdateTopology(HashSet::from([PeerId::from(
        kp1.public_key().clone(),
    )])));
    net1.update_topology(UpdateTopology([p2.id().clone()].into_iter().collect()));
    net1.update_peers_addresses(UpdatePeers(vec![(p2.id().clone(), addr2.clone())]));
    assert_peer_connects(&net1, p2.id()).await;
}

#[test]
fn caps_unit_fixture_raw_layout_is_exact() {
    use norito::core;
    let value = Dummy;
    for requested in [0, core::header_flags::COMPACT_LEN] {
        let (bytes, flags) = {
            let _flags = core::DecodeFlagsGuard::enter(requested);
            norito::codec::encode_with_header_flags(&value)
        };
        let _flags = core::DecodeFlagsGuard::enter(flags);
        let (decoded, used) = core::decode_field_canonical::<Dummy>(&bytes).unwrap();
        assert_eq!(used, bytes.len());
        assert!(bytes.len() <= 8);
        assert_eq!(
            Dummy::inbound_topic(&bytes, flags).unwrap(),
            Some(decoded.topic())
        );
        assert_eq!(
            Dummy::inbound_admission_class(&bytes, flags).unwrap(),
            decoded.admission_class()
        );
        assert!(Dummy::inbound_topic(&[0], flags).is_err());
        assert!(Dummy::inbound_topic(&bytes, flags | 0x80).is_err());
    }
}
