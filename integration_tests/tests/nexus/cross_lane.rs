//! Cross-lane manifest and relay proof tests (NX-11).
use eyre::Result;
use iroha_config::parameters::actual::{GovernanceCatalog, GovernanceModule, LaneRegistry};
use iroha_core::governance::manifest::{GovernanceGuardReason, LaneManifestRegistry};
use iroha_crypto::LaneCommitmentId;
use iroha_data_model::{
    nexus::{LaneCatalog, LaneConfig, LanePrivacyProof, LaneStorageProfile},
    proof::{ProofAttachment, ProofAttachmentList, ProofBox, VerifyingKeyId},
};
use iroha_model_base::peer::PeerId;
use iroha_model_base::topology::LaneId;
use iroha_test_samples::{ALICE_ID, BOB_ID};
use norito::{core as norito_core, json};
use std::{collections::BTreeMap, fs, num::NonZeroU32, path::Path, time::Duration};
use tempfile::tempdir;
#[test]
fn commitment_only_lane_without_privacy_commitments_is_gated() -> Result<()> {
    let alias = "private-lane";
    let lane_id = LaneId::new(42);
    let fixtures = tempdir()?;
    write_manifest(fixtures.path(), alias, false)?;
    let registry = build_registry(
        fixtures.path(),
        lane_id,
        alias,
        LaneStorageProfile::CommitmentOnly,
    )?;
    let err = registry
        .ensure_lane_ready(lane_id)
        .expect_err("lane should be rejected when privacy commitments are missing");
    assert_eq!(
        err.reason(),
        GovernanceGuardReason::MissingPrivacyCommitments
    );
    assert!(
        err.message().contains("privacy commitments"),
        "expected message to mention missing commitments, got: {}",
        err.message()
    );
    Ok(())
}
#[test]
fn commitment_only_lane_with_privacy_commitments_is_ready() -> Result<()> {
    let alias = "confidential-lane";
    let lane_id = LaneId::new(7);
    let fixtures = tempdir()?;
    write_manifest(fixtures.path(), alias, true)?;
    let registry = build_registry(
        fixtures.path(),
        lane_id,
        alias,
        LaneStorageProfile::CommitmentOnly,
    )?;
    registry
        .ensure_lane_ready(lane_id)
        .expect("lane with privacy commitments should be accepted");
    let status = registry
        .status(lane_id)
        .expect("lane status should be registered after manifest load");
    assert_eq!(
        status.privacy_commitments().len(),
        1,
        "lane manifest should expose the configured privacy commitment"
    );
    Ok(())
}
#[test]
fn lane_privacy_proof_attachment_roundtrips() -> Result<()> {
    let leaf = [0xAB_u8; 32];
    let sibling = [0xCD_u8; 32];
    let privacy = LanePrivacyProof::merkle_from_raw_path(
        LaneCommitmentId::new(9),
        leaf,
        0,
        vec![Some(sibling)],
    )?;
    let mut attachment = ProofAttachment::new_ref(
        "lane/privacy".parse()?,
        ProofBox::new("lane/privacy".parse()?, vec![0x01, 0x02]),
        VerifyingKeyId::new("lane/privacy", "lane_privacy_vk"),
    );
    attachment.lane_privacy = Some(privacy);
    let list = ProofAttachmentList::try_from(vec![attachment])
        .expect("one attachment is a valid bounded proof list");
    let norito_bytes = norito::to_bytes(&list)?;
    let archived = norito::from_bytes::<ProofAttachmentList>(&norito_bytes)?;
    let decoded: ProofAttachmentList = norito_core::DeserializePayload::deserialize(archived);
    assert_eq!(decoded, list);
    let decoded_privacy = decoded
        .as_slice()
        .first()
        .and_then(|entry| entry.lane_privacy.clone())
        .expect("lane privacy attachment present");
    assert_eq!(decoded_privacy.commitment_id, LaneCommitmentId::new(9));
    Ok(())
}
fn build_registry(
    manifest_dir: &Path,
    lane_id: LaneId,
    alias: &str,
    storage: LaneStorageProfile,
) -> Result<LaneManifestRegistry> {
    let lane_count = NonZeroU32::new(lane_id.as_u32() + 1).expect("lane count must be nonzero");
    let lane_catalog = LaneCatalog::new(
        lane_count,
        vec![LaneConfig {
            id: lane_id,
            alias: alias.to_string(),
            governance: Some("council".to_string()),
            storage,
            ..LaneConfig::default()
        }],
    )?;
    let mut governance_catalog = GovernanceCatalog::default();
    governance_catalog.modules.insert(
        "council".to_string(),
        GovernanceModule {
            module_type: Some("council".to_string()),
            params: BTreeMap::new(),
        },
    );
    let registry_cfg = LaneRegistry {
        manifest_directory: Some(manifest_dir.to_path_buf()),
        cache_directory: None,
        poll_interval: Duration::ZERO,
    };
    Ok(LaneManifestRegistry::from_config(
        &lane_catalog,
        &governance_catalog,
        &registry_cfg,
    ))
}
fn write_manifest(dir: &Path, alias: &str, include_privacy: bool) -> Result<()> {
    fs::create_dir_all(dir)?;
    let alice_peer = PeerId::from(ALICE_ID.expect_single_signatory().clone()).to_string();
    let bob_peer = PeerId::from(BOB_ID.expect_single_signatory().clone()).to_string();
    let mut alice_binding = norito::json::native::Map::new();
    alice_binding.insert("validator".into(), ALICE_ID.to_string().into());
    alice_binding.insert("peer_id".into(), alice_peer.into());
    let mut bob_binding = norito::json::native::Map::new();
    bob_binding.insert("validator".into(), BOB_ID.to_string().into());
    bob_binding.insert("peer_id".into(), bob_peer.into());
    let mut manifest = norito::json::native::Map::new();
    manifest.insert("lane".into(), norito::json!(alias));
    manifest.insert("governance".into(), norito::json!("council"));
    manifest.insert("version".into(), norito::json!(1));
    manifest.insert(
        "validators".into(),
        norito::json::native::Value::Array(vec![
            norito::json::native::Value::Object(alice_binding),
            norito::json::native::Value::Object(bob_binding),
        ]),
    );
    manifest.insert("quorum".into(), norito::json!(1));
    manifest.insert(
        "protected_namespaces".into(),
        norito::json!(["confidential"]),
    );
    if include_privacy {
        manifest.insert(
            "privacy_commitments".into(),
            norito::json!([{
                "id": 1,
                "scheme": "merkle",
                "merkle": {
                    "root": "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    "max_depth": 8
                }
            }]),
        );
    }
    let manifest = norito::json::native::Value::Object(manifest);
    let path = dir.join(format!("{alias}.manifest.json"));
    fs::write(&path, format!("{}\n", json::to_string_pretty(&manifest)?))?;
    Ok(())
}
