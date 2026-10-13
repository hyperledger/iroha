// Context ownership controls use attached local peers without starting validators.
fn context_owner_fixture() -> (tempfile::TempDir, NetworkPeer) {
    let directory = tempdir().expect("peer context directory");
    let environment = Environment {
        dir: directory.path().to_path_buf(),
    };
    let peer = NetworkPeer::builder().build(&environment);
    peer.client_config
        .set(PeerClientConfig {
            chain: config::chain_id(),
            network_id: NetworkId::from_genesis_hash(
                HashOf::<iroha_data_model::block::BlockHeader>::from_untyped_unchecked(
                    CryptoHash::prehashed([0xA5; CryptoHash::LENGTH]),
                ),
            ),
            chain_discriminant: defaults::common::chain_discriminant(),
            api_token: None,
            policy: PeerClientPolicy {
                status_timeout: Duration::from_secs(37),
                request_timeout: Duration::from_secs(3),
                ttl: Duration::from_secs(160),
            },
        })
        .expect("attach fixture exactly once");
    (directory, peer)
}

#[test]
fn peer_context_concurrent_clones_share_one_retained_owner() {
    let (_directory, peer) = context_owner_fixture();
    assert!(peer.retained_client.get().is_none());
    let addresses = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let peer = peer.clone();
                scope.spawn(move || {
                    let client = peer.client();
                    assert_eq!(client.client().account(), &*ALICE_ID);
                    assert_eq!(client.client().operator_key_pair(), Some(&peer.key_pair));
                    assert_eq!(
                        client.client().endpoint().as_str(),
                        format!("{}/", peer.torii_url())
                    );
                    peer.retained_client() as *const Client as usize
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert!(addresses.iter().all(|address| *address == addresses[0]));
    assert_eq!(
        peer.retained_client() as *const Client as usize,
        addresses[0]
    );
    assert!(!peer.is_running());
}

#[test]
fn peer_context_keeps_attached_policy_despite_later_environment_changes() {
    let _guard = lock_env_guard(&CONFIG_ENV_GUARD);
    let (_directory, peer) = context_owner_fixture();
    let _changed = [
        EnvVarRestore::set("IROHA_TEST_CLIENT_STATUS_TIMEOUT_SECS", "999"),
        EnvVarRestore::set("IROHA_TEST_CLIENT_REQUEST_TIMEOUT_SECS", "888"),
        EnvVarRestore::set("IROHA_TEST_CLIENT_TTL_SECS", "2200"),
    ];
    let alice = peer.client();
    let bob = peer.client_for(
        &BOB_ID,
        iroha_test_samples::BOB_KEYPAIR.private_key().clone(),
    );
    for client in [&alice, &bob] {
        assert_eq!(
            client.client().transaction_status_timeout(),
            Duration::from_secs(37)
        );
        assert_eq!(
            client.client().torii_request_timeout(),
            Duration::from_secs(3)
        );
        assert_eq!(
            client.client().transaction_ttl(),
            Some(Duration::from_secs(160))
        );
        assert_eq!(
            client.client().network_id(),
            &peer.client_config.get().unwrap().network_id
        );
        assert_eq!(client.client().operator_key_pair(), Some(&peer.key_pair));
    }
    assert_eq!(alice.client().account(), &*ALICE_ID);
    assert_eq!(bob.client().account(), &*BOB_ID);
    assert_eq!(peer.client().client().account(), &*ALICE_ID);
}

#[test]
fn peer_context_does_not_share_authority_or_endpoint_between_peers() {
    let (_first_directory, first) = context_owner_fixture();
    let (_second_directory, second) = context_owner_fixture();
    let a = first.client();
    let b = second.client();
    assert_ne!(a.client().endpoint(), b.client().endpoint());
    assert_ne!(
        a.client().operator_key_pair(),
        b.client().operator_key_pair()
    );
    assert!(!std::ptr::eq(
        first.retained_client(),
        second.retained_client()
    ));
    let mut changed_builder = a.client().to_builder();
    changed_builder.torii_request_timeout = Duration::from_secs(99);
    assert_eq!(
        first.client().client().torii_request_timeout(),
        Duration::from_secs(3)
    );
}
