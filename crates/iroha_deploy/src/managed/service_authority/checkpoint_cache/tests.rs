//! Real generated paid checkpoints exercise optional import reuse without supplying currentness.

use super::*;
use crate::{
    managed::{
        LocalnetPorts,
        native_operation::{
            MAX_CHECKPOINT_BYTES, checkpoint_bytes,
            test_support::{
                UnavailablePeers,
                native_fixture::{NativeFixture, quote_instructions},
            },
        },
        service_authority::NetworkPurpose,
    },
    verify::finality::FinalityVerifier,
};
use iroha_data_model::isi::{InstructionBox, Log};
use iroha_fs::{PrivateDirectory, PublishMode};
use std::{
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

fn attempts(authority: &ServiceAuthority) -> usize {
    authority
        .checkpoint_cache
        .decode_attempts
        .load(Ordering::Relaxed)
}

fn assert_entry(authority: &ServiceAuthority, bytes: &[u8]) {
    let slot = authority.checkpoint_cache.entry.try_lock().unwrap();
    let entry = slot.as_ref().expect("one successful original");
    assert_eq!(entry.bytes, bytes);
    assert_eq!(entry.network, authority.config.network_id);
    assert_eq!(entry.chain, authority.config.chain.as_str());
    assert_eq!(checkpoint_bytes(&entry.verifier).unwrap(), bytes);
    assert!(entry.bytes.len() <= MAX_CHECKPOINT_BYTES);
}

fn assert_refused(authority: &ServiceAuthority, bytes: &[u8]) {
    let expected = decode_checkpoint(
        bytes,
        authority.config.network_id,
        authority.config.chain.as_str(),
    )
    .unwrap_err()
    .to_string();
    let before = attempts(authority);
    assert_eq!(
        authority.decode_checkpoint(bytes).unwrap_err().to_string(),
        expected
    );
    assert_eq!(attempts(authority), before + 1);
    assert!(
        authority
            .checkpoint_cache
            .entry
            .try_lock()
            .unwrap()
            .is_none()
    );
}

#[test]
fn authenticated_single_checkpoint_reuse_preserves_scope_mutation_and_custody_checks() {
    let _guard = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let ports = LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet_at(
        "checkpoint-import",
        &temporary.path().join("generation"),
        &ports,
        crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    let mut authority =
        ServiceAuthority::open_network(&prepared, NetworkPurpose::BuildRegistry).unwrap();
    let mut native = NativeFixture::from_generated(&prepared, &authority);
    let signed = quote_instructions(
        &native,
        &authority.config,
        [InstructionBox::from(Log::new(
            iroha_data_model::Level::INFO,
            "original checkpoint import".into(),
        ))],
    );
    assert_eq!(native.chain.commit(vec![signed.clone()]), vec![true]);
    let original = native.observe(&authority);
    assert_eq!(original.checkpoint().height(), 2);
    let bytes = checkpoint_bytes(&original).unwrap();
    drop(ports);
    let unavailable = UnavailablePeers::start(&prepared);

    assert_eq!(attempts(&authority), 0);
    let mut returned = authority.decode_checkpoint(&bytes).unwrap();
    assert_eq!(returned, original);
    assert_eq!(attempts(&authority), 1);
    for _ in 0..3 {
        assert_eq!(authority.decode_checkpoint(&bytes).unwrap(), original);
    }
    assert_eq!(attempts(&authority), 1);
    assert_entry(&authority, &bytes);

    // Scope is read from the current explicit configuration on every hit, not from construction.
    let network = authority.config.network_id;
    authority.config.network_id =
        NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
            iroha_crypto::Hash::new(b"foreign checkpoint cache network"),
        ));
    assert_refused(&authority, &bytes);
    authority.config.network_id = network;
    authority.decode_checkpoint(&bytes).unwrap();
    let chain = authority.config.chain.clone();
    authority.config.chain = "00000000-0000-0000-0000-000000000001".parse().unwrap();
    assert_ne!(authority.config.chain, chain);
    assert_refused(&authority, &bytes);
    authority.config.chain = chain;

    // Exact supplied bytes remain mandatory, even when an authenticated old image was warm.
    authority.decode_checkpoint(&bytes).unwrap();
    let mut changed = bytes.clone();
    changed.push(0);
    assert_refused(&authority, &changed);
    assert_refused(&authority, &changed);
    authority.decode_checkpoint(&bytes).unwrap();
    assert_refused(&authority, &[]);
    authority.decode_checkpoint(&bytes).unwrap();
    assert_refused(&authority, &vec![0; MAX_CHECKPOINT_BYTES + 1]);

    // A caller's genuine fresh observation advances only its returned verifier.
    authority.decode_checkpoint(&bytes).unwrap();
    let next = quote_instructions(
        &native,
        &authority.config,
        [InstructionBox::from(Log::new(
            iroha_data_model::Level::INFO,
            "checkpoint import successor".into(),
        ))],
    );
    assert_eq!(native.chain.commit(vec![next]), vec![true]);
    assert_eq!(returned.observe(&native, &[17; 32]).unwrap().verified(), 4);
    assert_eq!(returned.checkpoint().height(), 3);
    assert_eq!(original.checkpoint().height(), 2);
    let before = attempts(&authority);
    assert_eq!(authority.decode_checkpoint(&bytes).unwrap(), original);
    assert_eq!(attempts(&authority), before);
    assert_entry(&authority, &bytes);
    let successor = checkpoint_bytes(&returned).unwrap();
    authority.decode_checkpoint(&successor).unwrap();
    assert_entry(&authority, &successor);
    assert_eq!(attempts(&authority), before + 1);
    authority.decode_checkpoint(&bytes).unwrap();
    assert_entry(&authority, &bytes);
    assert_eq!(attempts(&authority), before + 2);

    // Historical import reuse supplies neither original file custody nor a current observation.
    authority
        .directory
        .write_atomic("carrier.nrt", &bytes, PublishMode::CreateNew)
        .unwrap();
    assert_eq!(
        authority
            .retained_finality(&authority.directory, &signed)
            .unwrap()
            .unwrap()
            .height,
        2
    );
    std::fs::remove_file(authority.directory.path().join("carrier.nrt")).unwrap();
    assert!(
        authority
            .retained_finality(&authority.directory, &signed)
            .unwrap()
            .is_none()
    );
    authority
        .directory
        .write_atomic("current-checkpoint.nrt", &changed, PublishMode::CreateNew)
        .unwrap();
    let error = authority
        .observe_finality(Instant::now() + Duration::from_secs(60))
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("invalid retained native operation checkpoint")
    );
    assert!(unavailable.requests.lock().unwrap().is_empty());
    std::fs::remove_file(authority.directory.path().join("current-checkpoint.nrt")).unwrap();
    authority.decode_checkpoint(&bytes).unwrap();
    let generation =
        PrivateDirectory::open_exact(prepared.context.client_config.parent().unwrap()).unwrap();
    let peer = generation.read("peer3.toml", 1024 * 1024).unwrap();
    std::fs::remove_file(generation.path().join("peer3.toml")).unwrap();
    assert!(authority.validate_profile().is_err());
    // Existing bytes still prove their historical cut, never the missing live profile.
    assert_eq!(authority.decode_checkpoint(&bytes).unwrap(), original);
    generation
        .write_atomic("peer3.toml", &peer, PublishMode::CreateNew)
        .unwrap();
    authority.validate_profile().unwrap();

    // Optional cache synchronization cannot return a stale success or replace canonical errors.
    let held = authority.checkpoint_cache.entry.try_lock().unwrap();
    let before = attempts(&authority);
    assert_eq!(authority.decode_checkpoint(&bytes).unwrap(), original);
    assert!(authority.decode_checkpoint(&changed).is_err());
    assert_eq!(attempts(&authority), before + 2);
    drop(held);
    assert_entry(&authority, &bytes);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = authority.checkpoint_cache.entry.lock().unwrap();
            panic!("poison only the optional checkpoint memo");
        }))
        .is_err()
    );
    let before = attempts(&authority);
    assert!(authority.decode_checkpoint(&changed).is_err());
    assert_eq!(authority.decode_checkpoint(&bytes).unwrap(), original);
    assert_eq!(attempts(&authority), before + 2);
    let poisoned = match authority.checkpoint_cache.entry.try_lock() {
        Err(TryLockError::Poisoned(poisoned)) => poisoned,
        _ => panic!("optional memo remains poisoned"),
    };
    assert!(poisoned.into_inner().is_none());
    assert!(unavailable.requests.lock().unwrap().is_empty());
}

#[test]
fn checkpoint_reuse_preserves_service_authority_send_and_sync() {
    fn requires_send_sync<T: Send + Sync>() {}
    requires_send_sync::<ServiceAuthority>();
    requires_send_sync::<FinalityVerifier>();
}
