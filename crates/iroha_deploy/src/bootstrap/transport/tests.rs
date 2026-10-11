//! Exact installed-location retrieval and independent native-checkpoint authentication tests.

use super::*;
use iroha::http::{HttpTransport, TransportFuture, TransportRequest};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::sumeragi_finality::test_fixtures::NativeFinalityFixture;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

#[derive(Debug)]
struct Transport {
    bytes: Vec<u8>,
    requests: Mutex<Vec<TransportRequest>>,
}

impl HttpTransport for Transport {
    fn send_blocking(
        &self,
        request: TransportRequest,
    ) -> color_eyre::eyre::Result<iroha::http::Response<Vec<u8>>> {
        self.requests.lock().unwrap().push(request);
        Ok(iroha::http::Response::new(self.bytes.clone()))
    }
    fn send(&self, request: TransportRequest) -> TransportFuture<'_> {
        Box::pin(async move { self.send_blocking(request) })
    }
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

fn fixture() -> (InstalledNetworkProfile, Vec<u8>) {
    let checkpoint = NativeFinalityFixture::new().checkpoint();
    let key = KeyPair::from_seed(vec![61; 32], Algorithm::Ed25519);
    let release = crate::bootstrap::tests::metadata(&checkpoint);
    let bytes = crate::bootstrap::tests::signed(release, &checkpoint, &key);
    let profile = InstalledNetworkProfile::new(
        "fixture".into(),
        key.public_key().clone(),
        5,
        "https://installed.example/checkpoint.nrt".into(),
    )
    .unwrap();
    (profile, bytes)
}

fn transport(bytes: Vec<u8>) -> (CheckpointTransport, Arc<Transport>) {
    let raw = Arc::new(Transport {
        bytes,
        requests: Mutex::new(vec![]),
    });
    (
        CheckpointTransport::with_client(PublicHttpClient::with_transport(raw.clone())),
        raw,
    )
}

#[test]
fn checkpoint_reader_uses_exact_installed_unsigned_request_and_authenticates_native_checkpoint() {
    let _ = CheckpointTransport::new();
    let (profile, bytes) = fixture();
    let (reader, raw) = transport(bytes);
    let temporary = tempfile::tempdir().unwrap();
    let store = ReleaseCheckpointStore::open(&temporary.path().join("release")).unwrap();
    let authenticated = reader
        .fetch_with_clock(&profile, &store, deadline(), || Ok(2_000))
        .unwrap();
    assert_eq!(authenticated.release().network_name, "fixture");
    assert_eq!(authenticated.release().serial, 5);
    assert_eq!(
        authenticated.into_verifier().checkpoint().height(),
        NativeFinalityFixture::new().checkpoint().height()
    );
    let requests = raw.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.url, *profile.checkpoint_url());
    assert_eq!(request.method, iroha::http::Method::GET);
    assert!(request.headers.is_empty());
    assert!(request.body.is_empty());
    assert_eq!(request.max_response_bytes, MAX_DOWNLOADED_CHECKPOINT_BYTES);
    assert!(
        request
            .timeout
            .is_some_and(|value| value <= Duration::from_secs(5))
    );
    assert!(store.read_watermark().unwrap().accepted.is_some());
}

#[test]
fn downloaded_bytes_cannot_select_an_authority_label_or_floor_or_replace_installation() {
    let (profile, bytes) = fixture();
    let wrong_key = KeyPair::from_seed(vec![62; 32], Algorithm::Ed25519);
    for (name, key, floor) in [
        ("fixture", wrong_key.public_key(), 5),
        ("foreign", &profile.release_trust().public_key, 5),
        ("fixture", &profile.release_trust().public_key, 6),
    ] {
        let installed = InstalledNetworkProfile::new(
            name.into(),
            key.clone(),
            floor,
            profile.checkpoint_url().to_string(),
        )
        .unwrap();
        let (reader, raw) = transport(bytes.clone());
        let temporary = tempfile::tempdir().unwrap();
        let store = ReleaseCheckpointStore::open(&temporary.path().join("release")).unwrap();
        assert!(
            reader
                .fetch_with_clock(&installed, &store, deadline(), || Ok(2_000))
                .is_err()
        );
        assert_eq!(raw.requests.lock().unwrap().len(), 1);
        assert!(store.read_watermark().unwrap().accepted.is_none());
    }
    let installation = crate::bootstrap::InstalledNetworkProfiles::new(vec![profile.clone()])
        .unwrap()
        .encode_installation()
        .unwrap();
    for response in [bytes[..bytes.len() / 2].to_vec(), installation] {
        let (reader, _) = transport(response);
        let temporary = tempfile::tempdir().unwrap();
        let store = ReleaseCheckpointStore::open(&temporary.path().join("release")).unwrap();
        assert!(
            reader
                .fetch_with_clock(&profile, &store, deadline(), || Ok(2_000))
                .is_err()
        );
        assert!(store.read_watermark().unwrap().accepted.is_none());
    }
}

#[test]
fn checkpoint_reader_samples_expiry_after_download_and_does_not_publish_invalid_clock() {
    let (profile, bytes) = fixture();
    for now in [
        Ok(10_000),
        Err(BootstrapError::Invalid("local clock unavailable")),
    ] {
        let (reader, raw) = transport(bytes.clone());
        let temporary = tempfile::tempdir().unwrap();
        let store = ReleaseCheckpointStore::open(&temporary.path().join("release")).unwrap();
        assert!(
            reader
                .fetch_with_clock(&profile, &store, deadline(), || {
                    assert_eq!(raw.requests.lock().unwrap().len(), 1);
                    now
                })
                .is_err()
        );
        assert!(store.read_watermark().unwrap().accepted.is_none());
    }
    let (reader, raw) = transport(bytes);
    let temporary = tempfile::tempdir().unwrap();
    let store = ReleaseCheckpointStore::open(&temporary.path().join("release")).unwrap();
    assert!(
        reader
            .fetch_and_authenticate(&profile, &store, Instant::now())
            .is_err()
    );
    assert!(raw.requests.lock().unwrap().is_empty());
}
