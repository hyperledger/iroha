//! Original service transport inheritance preserves native custody and fresh peer contexts.

use super::*;
use iroha::http::{HttpTransport, Response, TransportFuture, TransportRequest};
use std::{sync::Mutex, time::Duration};

#[derive(Debug, Default)]
struct Captured(Mutex<Vec<TransportRequest>>);
impl HttpTransport for Captured {
    fn send_blocking(
        &self,
        request: TransportRequest,
    ) -> color_eyre::eyre::Result<Response<Vec<u8>>> {
        self.0.lock().unwrap().push(request);
        Ok(Response::builder()
            .header("Content-Type", "application/json")
            .body(norito::json::to_vec(&norito::json!({"fixture": true}))?)
            .unwrap())
    }
    fn send(&self, _: TransportRequest) -> TransportFuture<'_> {
        panic!("service finality clients retain their synchronous transport path")
    }
}
fn fixture() -> (tempfile::TempDir, ServiceAuthority) {
    let temporary = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet_at(
        "service-transports",
        &temporary.path().join("generation"),
        &ports,
        crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    let parent =
        ServiceAuthority::open_network(&prepared, NetworkPurpose::ServiceBootstrap).unwrap();
    (temporary, parent)
}
fn capture(parent: &mut ServiceAuthority) -> Arc<Captured> {
    let transport = Arc::new(Captured::default());
    parent.transport_seed = parent
        .transport_seed
        .to_builder()
        .http_transport(transport.clone())
        .build()
        .unwrap();
    transport
}

#[test]
fn original_service_children_reuse_private_transport_with_original_peer_identity() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, mut parent) = fixture();
    let transport = capture(&mut parent);
    let expected = parent.transport_seed.to_builder();
    let endpoints: Vec<_> = parent
        .peers
        .iter()
        .map(|(_, p)| p.endpoint().clone())
        .collect();
    // Mutable diagnostic projections cannot supply a child's identity or transport seed.
    parent.config.account = iroha_data_model::account::AccountId::new(
        iroha_crypto::KeyPair::from_seed(vec![94; 32], iroha_crypto::Algorithm::Ed25519)
            .public_key()
            .clone(),
    );
    parent.config.torii_request_timeout = Duration::from_secs(71);
    parent.peers.clear();
    let child =
        ServiceAuthority::open_network_from_original(&parent, NetworkPurpose::InitialReservePolicy)
            .unwrap();
    for ((_, client), endpoint) in child.peers.iter().zip(&endpoints) {
        let actual = client.to_builder();
        assert_eq!(&actual.torii_url, endpoint);
        assert_eq!(actual.account, expected.account);
        assert_eq!(actual.network_id, expected.network_id);
        assert_eq!(actual.chain, expected.chain);
        assert!(actual.key_pair == expected.key_pair);
        assert!(actual.headers == expected.headers);
        assert_eq!(actual.torii_request_timeout, expected.torii_request_timeout);
        client.get_node_capabilities_json().unwrap();
    }
    assert_eq!(transport.0.lock().unwrap().len(), 4);
    assert!(
        ServiceAuthority::open_network_existing_from_original(
            &parent,
            NetworkPurpose::InitialReservePolicy,
            None
        )
        .is_err(),
        "child retains its own native lock"
    );
    drop(child);
    let child = ServiceAuthority::open_network_existing_from_original(
        &parent,
        NetworkPurpose::InitialReservePolicy,
        None,
    )
    .unwrap()
    .unwrap();
    child.peers[0].1.get_node_capabilities_json().unwrap();
    assert_eq!(transport.0.lock().unwrap().len(), 5);
    child.validate_profile().unwrap();
    parent.validate_profile().unwrap();
}

#[test]
fn service_transport_reuse_preserves_deadline_and_refuses_original_custody_change() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, mut parent) = fixture();
    let transport = capture(&mut parent);
    let child =
        ServiceAuthority::open_network_from_original(&parent, NetworkPurpose::InitialReservePolicy)
            .unwrap();
    let expired = child.peers[0].1.with_request_deadline(Instant::now());
    assert!(
        expired
            .with_request_deadline(Instant::now() + Duration::from_secs(60))
            .get_node_capabilities_json()
            .is_err()
    );
    assert!(transport.0.lock().unwrap().is_empty());
    child.peers[1].1.get_node_capabilities_json().unwrap();
    assert_eq!(transport.0.lock().unwrap().len(), 1);
    drop(child);
    let path = parent.prepared.peers[0].config_path.clone();
    let bytes = iroha_fs::read_private(&path, 1024 * 1024).unwrap();
    let mut changed = bytes.to_vec();
    changed.extend_from_slice(b"\n# substituted profile\n");
    PrivateDirectory::open_exact(path.parent().unwrap())
        .unwrap()
        .write_atomic(
            path.file_name().unwrap(),
            &changed,
            iroha_fs::PublishMode::Replace,
        )
        .unwrap();
    assert!(
        ServiceAuthority::open_network_existing_from_original(
            &parent,
            NetworkPurpose::InitialReservePolicy,
            None
        )
        .is_err()
    );
    assert_eq!(transport.0.lock().unwrap().len(), 1);
}
