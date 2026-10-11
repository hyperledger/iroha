//! Real executed G1/H2 source custody and fresh private-staging regression controls.
//!
//! Injected HTTP transports carry actual Core-produced canonical proofs. No remote network,
//! fabricated QC, release-selected signer or synthetic execution result is used.

use super::*;
use crate::bootstrap::{ReleaseCheckpointStore, ReleaseTrust};
use iroha::http::{HttpTransport, PublicHttpClient, Response, TransportFuture, TransportRequest};
use iroha_core::{
    state::World,
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    isi::Log,
    level::Level,
    sns::{DATASPACE_ALIAS_SUFFIX_ID, NameSelectorV1},
};
use iroha_model_base::topology::DataSpaceId;
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

#[derive(Debug)]
struct Transport {
    responses: BTreeMap<String, Vec<u8>>,
    requests: Mutex<Vec<TransportRequest>>,
}
impl HttpTransport for Transport {
    fn send_blocking(
        &self,
        request: TransportRequest,
    ) -> color_eyre::eyre::Result<Response<Vec<u8>>> {
        let path = request.url.path().to_owned();
        self.requests.lock().unwrap().push(request);
        Ok(Response::builder()
            .header("content-type", "application/x-norito")
            .body(self.responses.get(&path).cloned().unwrap_or_default())
            .unwrap())
    }
    fn send(&self, request: TransportRequest) -> TransportFuture<'_> {
        Box::pin(async move { self.send_blocking(request) })
    }
}

struct Fixture {
    _temporary: tempfile::TempDir,
    attachment: PrivateDirectory,
    bootstrap: AuthenticatedBootstrap,
    spec: PrivateRootSpec,
    transport: CheckpointTransport,
    raw: Arc<Transport>,
    g1: Vec<u8>,
    h2: Vec<u8>,
}
impl Fixture {
    fn new() -> Self {
        let config = TestChainConfig::new(World::new(), 1_000);
        let signer = config.genesis_key.clone();
        let mut chain = CertifiedTestChain::start(config).unwrap();
        for time in [1_500, 2_000] {
            let transaction = chain.sign(
                &signer,
                [Log::new(Level::INFO, "real managed bootstrap source".into()).into()],
                time - 1,
            );
            assert_eq!(chain.commit_at(time, vec![transaction]), vec![true]);
        }
        let view = chain.state().view();
        let g1 = chain.committed(1).block().encode_wire().unwrap();
        let h2 = chain.committed(2).block().encode_wire().unwrap();
        let responses = [1_u64, 2]
            .into_iter()
            .map(|height| {
                let proof = iroha_core::sumeragi::finality::build_proof(&view, height).unwrap();
                assert_eq!(
                    proof.block_wire.as_slice(),
                    if height == 1 {
                        g1.as_slice()
                    } else {
                        h2.as_slice()
                    }
                );
                (
                    format!("/v1/bridge/finality/{height}"),
                    norito::encode_canonical(&proof).unwrap(),
                )
            })
            .collect();
        // This authenticated release checkpoint is already past H2, so its tip is not a source substitute.
        let checkpoint = iroha_core::sumeragi::finality::build_checkpoint(&view, 3).unwrap();
        assert_eq!(checkpoint.height(), 3);
        let release_key = KeyPair::from_seed(vec![0x63; 32], Algorithm::Ed25519);
        let temporary = tempfile::tempdir().unwrap();
        let release = ReleaseCheckpointStore::open(&temporary.path().join("release")).unwrap();
        let bootstrap = release
            .authenticate(
                &ReleaseTrust::new("fixture".into(), release_key.public_key().clone(), 5).unwrap(),
                &crate::bootstrap::tests::signed(
                    crate::bootstrap::tests::metadata(&checkpoint),
                    &checkpoint,
                    &release_key,
                ),
                2_000,
            )
            .unwrap();
        let attachment =
            PrivateDirectory::open_or_create(temporary.path().join("attachment")).unwrap();
        let alias = "managedamx";
        let selector = NameSelectorV1::new(DATASPACE_ALIAS_SUFFIX_ID, alias).unwrap();
        let spec = PrivateRootSpec {
            parent_network_id: chain.network_id(),
            dataspace_id: DataSpaceId::from_hash(&selector.name_hash()),
            dataspace_alias: alias.into(),
        };
        let raw = Arc::new(Transport {
            responses,
            requests: Mutex::new(vec![]),
        });
        let transport =
            CheckpointTransport::with_client(PublicHttpClient::with_transport(raw.clone()));
        Self {
            _temporary: temporary,
            attachment,
            bootstrap,
            spec,
            transport,
            raw,
            g1,
            h2,
        }
    }
    fn selection(&self) -> AmxSourceSelection<'_> {
        AmxSourceSelection {
            bootstrap: &self.bootstrap,
            attachment: &self.attachment,
            deadline: Instant::now() + Duration::from_secs(60),
        }
    }
    fn retain(&self, may_create: bool) -> Result<ParentBootstrapSources> {
        self.selection()
            .retain_with(&self.spec, may_create, &self.transport, || Ok(2_000))
    }
}

#[test]
fn managed_amx_sources_keep_original_g1_h2_across_advanced_checkpoint_and_reopen() {
    let fixture = Fixture::new();
    let before = fixture
        .bootstrap
        .verifier
        .checkpoint()
        .encode_canonical()
        .unwrap();
    let sources = fixture.retain(true).unwrap();
    let (g1, h2) = sources.read_pair().unwrap();
    assert_eq!(g1.as_slice(), fixture.g1.as_slice());
    assert_eq!(h2.as_slice(), fixture.h2.as_slice());
    drop(sources);
    let reopened = fixture.retain(false).unwrap();
    assert_eq!(
        reopened.read_pair().unwrap().0.as_slice(),
        fixture.g1.as_slice()
    );
    assert_eq!(
        fixture
            .bootstrap
            .verifier
            .checkpoint()
            .encode_canonical()
            .unwrap(),
        before
    );
    let requests = fixture.raw.requests.lock().unwrap();
    assert_eq!(
        requests.len(),
        2,
        "reopen must never refetch or replace original sources"
    );
    for (index, request) in requests.iter().enumerate() {
        assert_eq!(
            request.url.as_str(),
            format!("https://torii.example/v1/bridge/finality/{}", index + 1)
        );
        assert_eq!(request.headers.len(), 1);
        assert_eq!(request.headers[0].0.as_str(), "accept");
        assert_eq!(request.headers[0].1, "application/x-norito");
        assert!(request.body.is_empty());
    }
}

#[test]
fn managed_amx_sources_refuse_partial_removed_and_substituted_custody_without_http_repair() {
    for damage in [0_u8, 1, 2] {
        let fixture = Fixture::new();
        let sources = fixture.retain(true).unwrap();
        let directory = sources.directory.path().to_path_buf();
        drop(sources);
        match damage {
            0 => std::fs::remove_file(directory.join(H2)).unwrap(),
            1 => std::fs::write(directory.join(G1), b"substituted original source").unwrap(),
            _ => std::fs::remove_dir_all(directory).unwrap(),
        }
        assert!(fixture.retain(false).is_err());
        assert_eq!(fixture.raw.requests.lock().unwrap().len(), 2);
    }
    let fixture = Fixture::new();
    let partial = fixture.attachment.create_child(DIRECTORY).unwrap();
    partial
        .write_atomic(G1, &fixture.g1, iroha_fs::PublishMode::CreateNew)
        .unwrap();
    assert!(fixture.retain(true).is_err());
    assert!(fixture.raw.requests.lock().unwrap().is_empty());
    assert_eq!(
        partial
            .read(G1, SIGNED_GENESIS_MAX_BYTES_V1)
            .unwrap()
            .as_slice(),
        fixture.g1.as_slice()
    );
}

#[cfg(unix)]
#[test]
fn managed_amx_sources_bind_original_file_identity_and_exact_capsule_inventory() {
    let fixture = Fixture::new();
    let sources = fixture.retain(true).unwrap();
    sources
        .directory
        .write_atomic(G1, &fixture.g1, iroha_fs::PublishMode::Replace)
        .unwrap();
    assert!(
        sources.read_pair().is_err(),
        "same bytes in a replacement inode are not the retained original file"
    );
    assert_eq!(fixture.raw.requests.lock().unwrap().len(), 2);

    let fixture = Fixture::new();
    let sources = fixture.retain(true).unwrap();
    sources
        .directory
        .write_atomic("foreign.nrt", b"foreign", iroha_fs::PublishMode::CreateNew)
        .unwrap();
    assert!(
        sources.read_pair().is_err(),
        "a complete source capsule has exactly its three original files"
    );
    drop(sources);
    assert!(fixture.retain(false).is_err());
    assert_eq!(fixture.raw.requests.lock().unwrap().len(), 2);
}

#[test]
fn managed_amx_sources_refuse_wrong_parent_height_and_expired_reads_before_publication() {
    let fixture = Fixture::new();
    let mut wrong = fixture.spec.clone();
    wrong.parent_network_id = NetworkId::from_genesis_hash(
        iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(b"foreign parent")),
    );
    assert!(
        fixture
            .selection()
            .retain_with(&wrong, true, &fixture.transport, || Ok(2_000))
            .is_err()
    );
    assert!(fixture.raw.requests.lock().unwrap().is_empty());
    let expired = AmxSourceSelection {
        deadline: Instant::now(),
        ..fixture.selection()
    };
    assert!(
        expired
            .retain_with(&fixture.spec, true, &fixture.transport, || Ok(2_000))
            .is_err()
    );
    assert!(fixture.raw.requests.lock().unwrap().is_empty());
    let clock = AtomicUsize::new(0);
    assert!(
        fixture
            .selection()
            .retain_with(&fixture.spec, true, &fixture.transport, || {
                Ok(if clock.fetch_add(1, Ordering::SeqCst) == 0 {
                    2_000
                } else {
                    10_000
                })
            })
            .is_err()
    );
    assert!(
        fixture
            .attachment
            .open_child_optional(DIRECTORY)
            .unwrap()
            .is_none()
    );
    // Replace the exact height2 response with the genuine height1 frame: no invented corrupt QC.
    let mut replies = fixture.raw.responses.clone();
    replies.insert(
        "/v1/bridge/finality/2".into(),
        replies["/v1/bridge/finality/1"].clone(),
    );
    let raw = Arc::new(Transport {
        responses: replies,
        requests: Mutex::new(vec![]),
    });
    let transport = CheckpointTransport::with_client(PublicHttpClient::with_transport(raw));
    assert!(
        fixture
            .selection()
            .retain_with(&fixture.spec, true, &transport, || Ok(2_000))
            .is_err()
    );
    assert!(
        fixture
            .attachment
            .open_child_optional(DIRECTORY)
            .unwrap()
            .is_none()
    );
}

#[test]
fn managed_amx_sources_recheck_release_after_retained_authentication_without_refetch() {
    let fixture = Fixture::new();
    let original = fixture.retain(true).unwrap();
    drop(original);
    let clock = AtomicUsize::new(0);
    let result = fixture
        .selection()
        .retain_with(&fixture.spec, false, &fixture.transport, || {
            Ok(if clock.fetch_add(1, Ordering::SeqCst) == 0 {
                2_000
            } else {
                10_000
            })
        });
    assert!(matches!(
        result,
        Err(BootstrapError::Invalid(
            "AMX sources require the original live selected parent release"
        ))
    ));
    assert_eq!(fixture.raw.requests.lock().unwrap().len(), 2);
    let reopened = fixture.retain(false).unwrap();
    let (g1, h2) = reopened.read_pair().unwrap();
    assert_eq!(g1.as_slice(), fixture.g1.as_slice());
    assert_eq!(h2.as_slice(), fixture.h2.as_slice());
}

#[test]
fn managed_amx_sources_feed_real_private_staging_and_exact_retained_generation() {
    let _guard = crate::managed::native_test_guard();
    let fixture = Fixture::new();
    let sources = fixture.retain(true).unwrap();
    let child = fixture._temporary.path().join("private");
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_private_root_with_amx_at(
        "private",
        &child,
        &ports,
        &fixture.spec,
        None,
        &sources,
    )
    .unwrap();
    sources.require_signed_generation(&prepared).unwrap();
    let original = std::fs::read(child.join("genesis.signed.nrt")).unwrap();
    let reopened_sources = fixture.retain(false).unwrap();
    let reopened = crate::localnet::prepare_private_root_with_amx_at(
        "private",
        &child,
        &ports,
        &fixture.spec,
        None,
        &reopened_sources,
    )
    .unwrap();
    assert_eq!(prepared, reopened);
    assert_eq!(
        std::fs::read(child.join("genesis.signed.nrt")).unwrap(),
        original
    );
    assert_eq!(fixture.raw.requests.lock().unwrap().len(), 2);
    let registration = reopened.load_private_registration().unwrap();
    assert_eq!(registration.scope, fixture.spec.scope());
}

#[test]
fn managed_amx_sources_reopen_refuses_identical_g1_h2_replacement_without_http_repair() {
    for name in [G1, H2] {
        let fixture = Fixture::new();
        let sources = fixture.retain(true).unwrap();
        let original =
            iroha_fs::FileIdentity::of(&sources.directory.open_read(name).unwrap()).unwrap();
        drop(sources);
        let directory = fixture.attachment.open_child(DIRECTORY).unwrap();
        directory
            .write_atomic(
                name,
                if name == G1 { &fixture.g1 } else { &fixture.h2 },
                iroha_fs::PublishMode::Replace,
            )
            .unwrap();
        assert_ne!(
            iroha_fs::FileIdentity::of(&directory.open_read(name).unwrap()).unwrap(),
            original
        );
        drop(directory);
        assert!(
            matches!(
                fixture.retain(false),
                Err(BootstrapError::Invalid(
                    "AMX source objects differ from their original local publication"
                ))
            ),
            "reopen must refuse same bytes in a substituted original native file"
        );
        assert_eq!(
            fixture.raw.requests.lock().unwrap().len(),
            2,
            "a published generation cannot repair original custody over HTTP"
        );
    }
}

#[test]
fn managed_amx_sources_reopen_preserves_original_native_pair_and_directory_without_new_reads() {
    let fixture = Fixture::new();
    let sources = fixture.retain(true).unwrap();
    let directory_identity = sources.directory.identity().unwrap();
    let identities = [RECORD, G1, H2].map(|name| {
        iroha_fs::FileIdentity::of(&sources.directory.open_read(name).unwrap()).unwrap()
    });
    drop(sources);
    for _ in 0..2 {
        let reopened = fixture.retain(false).unwrap();
        assert_eq!(reopened.directory.identity().unwrap(), directory_identity);
        for (name, original) in [RECORD, G1, H2].into_iter().zip(identities) {
            assert_eq!(
                iroha_fs::FileIdentity::of(&reopened.directory.open_read(name).unwrap()).unwrap(),
                original
            );
        }
        let (g1, h2) = reopened.read_pair().unwrap();
        assert_eq!(g1.as_slice(), fixture.g1.as_slice());
        assert_eq!(h2.as_slice(), fixture.h2.as_slice());
    }
    assert_eq!(fixture.raw.requests.lock().unwrap().len(), 2);
}

#[test]
fn managed_amx_sources_refuse_incomplete_staging_without_refetch_or_new_deadline() {
    let fixture = Fixture::new();
    let stage = fixture.attachment.create_child(STAGING).unwrap();
    stage
        .write_atomic(G1, &fixture.g1, iroha_fs::PublishMode::CreateNew)
        .unwrap();
    assert!(matches!(
        fixture.retain(true),
        Err(BootstrapError::Invalid(
            "incomplete original AMX source publication"
        ))
    ));
    assert!(fixture.raw.requests.lock().unwrap().is_empty());
    assert_eq!(
        stage
            .read(G1, SIGNED_GENESIS_MAX_BYTES_V1)
            .unwrap()
            .as_slice(),
        fixture.g1.as_slice()
    );
    assert!(
        fixture
            .attachment
            .open_child_optional(DIRECTORY)
            .unwrap()
            .is_none()
    );
}
