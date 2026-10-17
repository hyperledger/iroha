use super::*;
fn checkpoint_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        PathBuf::from(r"C:\iroha\sorafs\evidence-viewer.to")
    }
    #[cfg(not(target_os = "windows"))]
    {
        PathBuf::from("/var/lib/iroha/sorafs/evidence-viewer.to")
    }
}
fn receipt_public_key_hex() -> String {
    let key = KeyPair::try_from_seed(vec![0x61; 32], Algorithm::Ed25519).expect("test keypair");
    hex::encode(key.public_key().to_bytes().1)
}
fn archive_public_key_hex() -> String {
    let key = KeyPair::try_from_seed(vec![0x62; 32], Algorithm::Ed25519).expect("test keypair");
    hex::encode(key.public_key().to_bytes().1)
}
fn transparency_publisher_public_key_hex() -> String {
    let key = KeyPair::try_from_seed(vec![0x63; 32], Algorithm::Ed25519).expect("test keypair");
    hex::encode(key.public_key().to_bytes().1)
}
fn valid_config() -> SorafsEvidenceViewerConfig {
    SorafsEvidenceViewerConfig {
        enabled: true,
        checkpoint_path: checkpoint_path(),
        checkpoint_store_handle: Some("sealed.evidence-viewer.checkpoints.primary".to_owned()),
        checkpoint_store_revision: Some(15),
        checkpoint_store_policy_digest_hex: Some("a5".repeat(32)),
        webauthn_rp_id: Some("review.example".to_owned()),
        webauthn_allowed_origins: vec!["https://review.example".to_owned()],
        webauthn_handle: Some("webauthn.evidence.primary".to_owned()),
        webauthn_revision: Some(11),
        webauthn_policy_digest_hex: Some("a1".repeat(32)),
        grant_handle: Some("kms.evidence.grants.primary".to_owned()),
        grant_revision: Some(12),
        grant_policy_digest_hex: Some("a2".repeat(32)),
        erasure_handle: Some("kms.evidence.erasure.primary".to_owned()),
        erasure_revision: Some(13),
        erasure_policy_digest_hex: Some("a3".repeat(32)),
        compaction_archive_handle: Some("object-lock.evidence.compaction.primary".to_owned()),
        compaction_archive_id_hex: Some("a6".repeat(32)),
        compaction_archive_revision: Some(16),
        compaction_archive_policy_digest_hex: Some("a7".repeat(32)),
        compaction_archive_public_key_hex: Some(archive_public_key_hex()),
        receipt_signer_handle: Some("software://sorafs/evidence-viewer/primary".to_owned()),
        receipt_signer_revision: Some(14),
        receipt_signer_policy_digest_hex: Some("a4".repeat(32)),
        receipt_signer_public_key_hex: Some(receipt_public_key_hex()),
        transparency_publisher_handle: Some("transparency.evidence.publisher.primary".to_owned()),
        transparency_publisher_revision: Some(17),
        transparency_publisher_policy_digest_hex: Some("a8".repeat(32)),
        transparency_publisher_public_key_hex: Some(transparency_publisher_public_key_hex()),
        ..SorafsEvidenceViewerConfig::default()
    }
}
#[test]
fn enabled_policy_binds_exact_runtime_qualifications() {
    let mut emitter = Emitter::new();
    let parsed = valid_config()
        .parse(true, &mut emitter)
        .expect("enabled evidence-viewer policy");
    assert!(emitter.into_result().is_ok());
    assert_eq!(
        parsed.checkpoint_store_handle,
        "sealed.evidence-viewer.checkpoints.primary"
    );
    assert_eq!(parsed.checkpoint_store_revision, 15);
    assert_eq!(parsed.checkpoint_store_policy_digest, [0xA5; 32]);
    assert_eq!(parsed.webauthn_revision, 11);
    assert_eq!(parsed.webauthn_policy_digest, [0xA1; 32]);
    assert_eq!(parsed.grant_revision, 12);
    assert_eq!(parsed.grant_policy_digest, [0xA2; 32]);
    assert_eq!(parsed.erasure_revision, 13);
    assert_eq!(parsed.erasure_policy_digest, [0xA3; 32]);
    assert_eq!(
        parsed.compaction_archive_handle,
        "object-lock.evidence.compaction.primary"
    );
    assert_eq!(parsed.compaction_archive_id, [0xA6; 32]);
    assert_eq!(parsed.compaction_archive_revision, 16);
    assert_eq!(parsed.compaction_archive_policy_digest, [0xA7; 32]);
    assert_eq!(parsed.compaction_interval, Duration::from_secs(60));
    assert_eq!(parsed.compaction_max_records, 256);
    assert_eq!(parsed.receipt_signer_revision, 14);
    assert_eq!(parsed.receipt_signer_policy_digest, [0xA4; 32]);
    assert_eq!(
        parsed.transparency_publisher_handle,
        "transparency.evidence.publisher.primary"
    );
    assert_eq!(parsed.transparency_publisher_revision, 17);
    assert_eq!(parsed.transparency_publisher_policy_digest, [0xA8; 32]);
    assert_eq!(
        hex::encode(parsed.transparency_publisher_public_key),
        transparency_publisher_public_key_hex()
    );
}
#[test]
fn enabled_policy_rejects_noncanonical_webauthn_rp_ids_and_origins() {
    for rp_id in ["Review.example", "localhost", "127.0.0.1"] {
        let mut config = valid_config();
        config.webauthn_rp_id = Some(rp_id.to_owned());
        let mut emitter = Emitter::new();
        assert!(
            config.parse(true, &mut emitter).is_none(),
            "{rp_id:?} must fail closed"
        );
        assert!(emitter.into_result().is_err());
    }
    for origin in [
        "http://review.example",
        "https://operator:secret@review.example",
        "https://review.example/path",
        "https://review.example?challenge=1",
        "https://review.example#fragment",
        "https://review.example:443",
        "https://foreign.example",
    ] {
        let mut config = valid_config();
        config.webauthn_allowed_origins = vec![origin.to_owned()];
        let mut emitter = Emitter::new();
        let _ = config.parse(true, &mut emitter);
        assert!(
            emitter.into_result().is_err(),
            "{origin:?} must fail closed"
        );
    }
    let mut canonical = valid_config();
    canonical.webauthn_allowed_origins = vec!["https://login.review.example:8443".to_owned()];
    let mut emitter = Emitter::new();
    assert!(canonical.parse(true, &mut emitter).is_some());
    assert!(emitter.into_result().is_ok());
}
#[test]
fn enabled_policy_rejects_missing_stale_or_noncanonical_qualifications() {
    let mut missing = valid_config();
    missing.checkpoint_store_handle = None;
    let mut emitter = Emitter::new();
    assert!(missing.parse(true, &mut emitter).is_none());
    assert!(emitter.into_result().is_err());
    let mut config = valid_config();
    config.webauthn_revision = Some(0);
    config.grant_policy_digest_hex = Some("A2".repeat(32));
    config.erasure_policy_digest_hex = Some("00".repeat(32));
    config.compaction_archive_id_hex = Some("00".repeat(32));
    config.compaction_archive_revision = Some(0);
    config.compaction_archive_policy_digest_hex = Some("A7".repeat(32));
    config.compaction_interval_ms = 999;
    config.compaction_max_records = 1_025;
    config.receipt_signer_revision = None;
    config.checkpoint_store_handle = Some("sealed.evidence-viewer.test".to_owned());
    config.checkpoint_store_revision = Some(0);
    config.checkpoint_store_policy_digest_hex = Some("A5".repeat(32));
    let mut emitter = Emitter::new();
    assert!(config.parse(true, &mut emitter).is_none());
    assert!(emitter.into_result().is_err());
}
#[test]
fn transparency_publisher_binding_is_required_and_canonical() {
    let mutations: [fn(&mut SorafsEvidenceViewerConfig); 11] = [
        |config| config.transparency_publisher_handle = None,
        |config| config.transparency_publisher_revision = None,
        |config| config.transparency_publisher_revision = Some(0),
        |config| config.transparency_publisher_policy_digest_hex = None,
        |config| config.transparency_publisher_policy_digest_hex = Some("A8".repeat(32)),
        |config| config.transparency_publisher_policy_digest_hex = Some("00".repeat(32)),
        |config| config.transparency_publisher_public_key_hex = None,
        |config| config.transparency_publisher_public_key_hex = Some("AA".repeat(32)),
        |config| config.transparency_publisher_public_key_hex = Some("00".repeat(32)),
        |config| config.transparency_publisher_public_key_hex = Some("ff".repeat(32)),
        |config| {
            config.transparency_publisher_handle =
                Some("transparency.evidence.publisher.test".to_owned());
        },
    ];
    for mutate in mutations {
        let mut config = valid_config();
        mutate(&mut config);
        let mut emitter = Emitter::new();
        assert!(config.parse(true, &mut emitter).is_none());
        assert!(emitter.into_result().is_err());
    }
}
#[test]
fn disabled_policy_requires_no_checkpoint_store_and_rejects_stray_binding() {
    let mut emitter = Emitter::new();
    assert!(
        SorafsEvidenceViewerConfig::default()
            .parse(true, &mut emitter)
            .is_none()
    );
    assert!(emitter.into_result().is_ok());
    let config = SorafsEvidenceViewerConfig {
        checkpoint_store_handle: Some("sealed.evidence-viewer.checkpoints.primary".to_owned()),
        ..SorafsEvidenceViewerConfig::default()
    };
    let mut emitter = Emitter::new();
    assert!(config.parse(true, &mut emitter).is_none());
    assert!(emitter.into_result().is_err());
    let config = SorafsEvidenceViewerConfig {
        compaction_archive_handle: Some("object-lock.evidence.compaction.primary".to_owned()),
        ..SorafsEvidenceViewerConfig::default()
    };
    let mut emitter = Emitter::new();
    assert!(config.parse(true, &mut emitter).is_none());
    assert!(emitter.into_result().is_err());
    let config = SorafsEvidenceViewerConfig {
        transparency_publisher_handle: Some("transparency.evidence.publisher.primary".to_owned()),
        ..SorafsEvidenceViewerConfig::default()
    };
    let mut emitter = Emitter::new();
    assert!(config.parse(true, &mut emitter).is_none());
    assert!(emitter.into_result().is_err());
}
