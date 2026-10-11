//! Offline file-loader coverage using actual signed cross-host phase checkpoints.

use super::*;
use crate::taira_public_reset::host_pair::{HostPhaseClaimsV1, HostPhaseV1, SignedHostPhaseV1};

#[cfg(unix)]
#[test]
fn retained_host_checkpoint_loader_keeps_initial_absence_required_gap_canonical_chain_and_original_custody_retry()
 {
    use std::os::unix::fs::PermissionsExt as _;

    let temporary = tempfile::tempdir().unwrap();
    let directory =
        iroha_fs::PrivateDirectory::open_or_create(temporary.path().join("checkpoints")).unwrap();
    let mut admitted = super::tests::admitted_reset_fixture();
    let key =
        iroha_crypto::KeyPair::try_from_seed(vec![0x8e; 32], iroha_crypto::Algorithm::Ed25519)
            .unwrap();
    admitted.inventory.operator_public_key = key.public_key().to_string();
    admitted.inventory_bytes =
        super::super::canonical_inventory_bytes(&admitted.inventory).unwrap();
    admitted.inventory_sha256 = sha256_hex(&admitted.inventory_bytes);
    admitted.authorization.claims.inventory_sha256 = admitted.inventory_sha256.clone();
    let signature = iroha_crypto::Signature::try_new(
        key.private_key(),
        &super::super::authorization_message(&admitted.authorization.claims).unwrap(),
    )
    .unwrap();
    admitted.authorization.signature_hex = hex::encode(signature.payload());
    admitted.trusted_key.public_key = key.public_key().to_string();
    admitted.authorization_bytes = json::to_vec(&admitted.authorization).unwrap();
    admitted.trusted_key_bytes = json::to_vec(&admitted.trusted_key).unwrap();
    admitted.authorization_sha256 =
        authorization_semantic_sha256(&admitted.authorization, &admitted.trusted_key).unwrap();
    let mut originals: Vec<(SignedHostPhaseV1, Vec<u8>)> = Vec::new();
    for phase in [
        HostPhaseV1::CandidateFrontier,
        HostPhaseV1::NativeEdgeReady,
        HostPhaseV1::DeploymentProven,
    ] {
        let inventory = &admitted.inventory;
        let hosts = &inventory.hosts;
        let previous = originals.last().map(|(checkpoint, _)| checkpoint);
        let checkpoint = SignedHostPhaseV1::sign(
            HostPhaseClaimsV1 {
                schema: "iroha.taira.public-reset.host-phase-checkpoint.v1".into(),
                phase,
                deployment_id: inventory.deployment_id.clone(),
                inventory_sha256: admitted.inventory_sha256.clone(),
                authorization_sha256: admitted.authorization_sha256.clone(),
                authorization_nonce: inventory.authorization_nonce.clone(),
                host_pair_sha256: hosts.digest().unwrap(),
                guest_host_identity_sha256: hosts
                    .validator_guest
                    .endpoint
                    .host_identity_sha256
                    .clone(),
                native_edge_host_identity_sha256: hosts
                    .native_edge
                    .endpoint
                    .host_identity_sha256
                    .clone(),
                guest_custody_root: hosts.validator_guest.custody_root.clone(),
                native_edge_custody_root: hosts.native_edge.custody_root.clone(),
                source_commit: inventory.revision.commit.clone(),
                next_genesis_hash: inventory.next_genesis_hash.clone(),
                evidence_sha256: "4".repeat(64),
                predecessor_sha256: previous.map(SignedHostPhaseV1::digest).transpose().unwrap(),
                execution_expires_at_unix_ms: admitted
                    .authorization
                    .claims
                    .execution_expires_at_unix_ms,
            },
            &key,
        )
        .unwrap();
        checkpoint
            .verify(
                inventory,
                &admitted.inventory_sha256,
                &admitted.authorization_sha256,
                admitted.authorization.claims.execution_expires_at_unix_ms,
                previous,
            )
            .unwrap();
        let bytes = json::to_vec(&checkpoint).unwrap();
        assert_eq!(checkpoint.digest().unwrap(), sha256_hex(&bytes));
        originals.push((checkpoint, bytes));
    }
    let root = directory.path();
    assert!(
        phases::load_checkpoints(root, &admitted, 3, false)
            .unwrap()
            .is_empty()
    );
    let required = phases::load_checkpoints(root, &admitted, 1, true).unwrap_err();
    assert_eq!(
        required.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::NotFound
    );
    assert!(phases::load_checkpoints(root, &admitted, 4, false).is_err());
    directory
        .write_atomic(
            "checkpoint-2.json",
            &originals[1].1,
            iroha_fs::PublishMode::CreateNew,
        )
        .unwrap();
    let gap = phases::load_checkpoints(root, &admitted, 2, false).unwrap_err();
    assert!(gap.to_string().contains("missing predecessor"));
    directory
        .write_atomic(
            "checkpoint-1.json",
            &originals[0].1,
            iroha_fs::PublishMode::CreateNew,
        )
        .unwrap();
    for (maximum, required) in [(1, false), (2, false), (2, true)] {
        let read = phases::load_checkpoints(root, &admitted, maximum, required).unwrap();
        assert_eq!(read.len(), maximum);
        for (actual, (original, _)) in read.iter().zip(&originals) {
            assert_eq!(actual.digest().unwrap(), original.digest().unwrap());
        }
    }
    directory
        .write_atomic(
            "checkpoint-3.json",
            &originals[2].1,
            iroha_fs::PublishMode::CreateNew,
        )
        .unwrap();
    let loaded = phases::load_checkpoints(root, &admitted, 3, true).unwrap();
    assert_eq!(loaded.len(), 3);
    let third = root.join("checkpoint-3.json");
    let saved = root.join("saved-original");
    std::fs::rename(&third, &saved).unwrap();
    let mut noncanonical = originals[2].1.clone();
    noncanonical.push(b'\n');
    directory
        .write_atomic(
            "checkpoint-3.json",
            &noncanonical,
            iroha_fs::PublishMode::CreateNew,
        )
        .unwrap();
    let error = phases::load_checkpoints(root, &admitted, 3, true).unwrap_err();
    assert!(error.to_string().contains("canonical signed body"));
    std::fs::remove_file(&third).unwrap();
    std::fs::rename(&saved, &third).unwrap();
    let displaced = temporary.path().join("displaced");
    std::fs::rename(root, &displaced).unwrap();
    let error = phases::load_checkpoints(root, &admitted, 3, false).unwrap_err();
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::NotFound
    );
    std::fs::rename(&displaced, root).unwrap();
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o755)).unwrap();
    let error = phases::load_checkpoints(root, &admitted, 3, false).unwrap_err();
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
    for (maximum, required) in [(3, false), (3, true)] {
        let read = phases::load_checkpoints(root, &admitted, maximum, required).unwrap();
        assert_eq!(read.len(), 3);
        for (ordinal, (actual, (original, bytes))) in read.iter().zip(&originals).enumerate() {
            assert_eq!(actual.digest().unwrap(), original.digest().unwrap());
            assert_eq!(
                directory
                    .read(format!("checkpoint-{}.json", ordinal + 1), 16 * 1024)
                    .unwrap()
                    .as_slice(),
                bytes.as_slice()
            );
        }
    }
}
