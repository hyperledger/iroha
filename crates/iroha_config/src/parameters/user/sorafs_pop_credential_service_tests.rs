//! Focused parser tests for the `SoraFS` `PoP` credential-service policy.
use super::*;
fn ed25519_public_hex(seed: u8) -> String {
    let key = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519).expect("key");
    hex::encode(key.public_key().to_bytes().1)
}
fn valid_config() -> SorafsPopCredentialService {
    SorafsPopCredentialService {
        enabled: true,
        issuer_state_dir: PathBuf::from("/var/lib/iroha/sorafs/pop/issuer"),
        wallet_state_dir: PathBuf::from("/var/lib/iroha/sorafs/pop/wallet"),
        issuer_policy_digest_hex: Some("41".repeat(32)),
        issuer_id: Some("pop-issuer-sora-foundation".to_owned()),
        issuer_signer_handle: Some("software://sorafs/pop-credentials/primary".to_owned()),
        issuer_public_key_hex: Some(ed25519_public_hex(0x11)),
        enrollment_recipient_key_id: Some("kms://pop/enrollment/primary".to_owned()),
        enrollment_recipient_public_key_digest_hex: Some("61".repeat(32)),
        wallet_recipient_key_id: Some("kms://pop/wallet-recipient/primary".to_owned()),
        wallet_recipient_public_key_digest_hex: Some("62".repeat(32)),
        wallet_wrapping_key_id: Some("kms://pop/wallet/primary".to_owned()),
        runtime_provider_registry_handle: Some("runtime://pop/providers/primary".to_owned()),
        runtime_provider_registry_revision: Some(7),
        runtime_provider_registry_policy_digest_hex: Some("51".repeat(32)),
        approval_quorum: 2,
        approval_signers: vec![
            SorafsPopApprovalSigner {
                signer_id: "approver-a".to_owned(),
                public_key_hex: ed25519_public_hex(0x21),
                revoked_at_epoch: None,
            },
            SorafsPopApprovalSigner {
                signer_id: "approver-b".to_owned(),
                public_key_hex: ed25519_public_hex(0x22),
                revoked_at_epoch: None,
            },
        ],
        ..SorafsPopCredentialService::default()
    }
}
fn assert_rejected(config: SorafsPopCredentialService) {
    let mut emitter = Emitter::new();
    assert!(config.parse(true, &mut emitter).is_none());
    assert!(emitter.into_result().is_err());
}
#[test]
fn governed_pop_policy_parses_without_runtime_secrets() {
    let mut emitter = Emitter::new();
    let parsed = valid_config()
        .parse(true, &mut emitter)
        .expect("enabled policy");
    assert!(emitter.into_result().is_ok());
    assert_eq!(parsed.issuer_policy_digest, [0x41; 32]);
    assert_eq!(parsed.approval_quorum, 2);
    assert_eq!(parsed.approval_signers.len(), 2);
    assert_eq!(parsed.worker_interval, Duration::from_secs(1));
    assert_eq!(parsed.max_finalized_time_skew, Duration::from_secs(30));
    assert_eq!(parsed.enrollment_recipient_public_key_digest, [0x61; 32]);
    assert_eq!(
        parsed.wallet_recipient_key_id,
        "kms://pop/wallet-recipient/primary"
    );
    assert_eq!(parsed.wallet_recipient_public_key_digest, [0x62; 32]);
    assert_eq!(parsed.wallet_wrapping_key_id, "kms://pop/wallet/primary");
    assert_eq!(
        parsed.runtime_provider_registry_handle,
        "runtime://pop/providers/primary"
    );
    assert_eq!(parsed.runtime_provider_registry_revision, 7);
    assert_eq!(parsed.runtime_provider_registry_policy_digest, [0x51; 32]);
}
#[test]
fn disabled_pop_policy_rejects_stale_authority_claims() {
    let config = SorafsPopCredentialService {
        issuer_id: Some("stale-authority".to_owned()),
        ..SorafsPopCredentialService::default()
    };
    let mut emitter = Emitter::new();
    assert!(config.parse(false, &mut emitter).is_none());
    assert!(emitter.into_result().is_err());
}
#[test]
fn unsafe_pop_policy_fails_closed() {
    let mut config = valid_config();
    config.issuer_state_dir = PathBuf::from("relative/issuer");
    config.issuer_policy_digest_hex = Some("AA".repeat(32));
    config.approval_signers[1].signer_id = "approver-a".to_owned();
    config.approval_signers[1].public_key_hex = config.approval_signers[0].public_key_hex.clone();
    config.approval_signers[1].revoked_at_epoch = Some(0);
    config.max_seen_nullifiers = 0;
    config.worker_interval_ms = 0;
    config.max_finalized_time_skew_secs = 301;
    let mut emitter = Emitter::new();
    assert!(config.parse(true, &mut emitter).is_none());
    assert!(emitter.into_result().is_err());
}
#[test]
fn enabled_pop_policy_requires_storage_and_dual_control() {
    let mut config = valid_config();
    config.approval_quorum = 1;
    config.approval_signers.truncate(1);
    let mut emitter = Emitter::new();
    let _ = config.parse(false, &mut emitter);
    assert!(emitter.into_result().is_err());
}
#[test]
fn enabled_pop_policy_rejects_missing_or_stale_provider_qualification() {
    let missing_handle = {
        let mut config = valid_config();
        config.runtime_provider_registry_handle = None;
        config
    };
    let missing_revision = {
        let mut config = valid_config();
        config.runtime_provider_registry_revision = None;
        config
    };
    let zero_revision = {
        let mut config = valid_config();
        config.runtime_provider_registry_revision = Some(0);
        config
    };
    let missing_digest = {
        let mut config = valid_config();
        config.runtime_provider_registry_policy_digest_hex = None;
        config
    };
    let missing_enrollment_recipient_digest = {
        let mut config = valid_config();
        config.enrollment_recipient_public_key_digest_hex = None;
        config
    };
    let zero_enrollment_recipient_digest = {
        let mut config = valid_config();
        config.enrollment_recipient_public_key_digest_hex = Some("00".repeat(32));
        config
    };
    let missing_wallet_recipient_digest = {
        let mut config = valid_config();
        config.wallet_recipient_public_key_digest_hex = None;
        config
    };
    let zero_wallet_recipient_digest = {
        let mut config = valid_config();
        config.wallet_recipient_public_key_digest_hex = Some("00".repeat(32));
        config
    };
    let zero_digest = {
        let mut config = valid_config();
        config.runtime_provider_registry_policy_digest_hex = Some("00".repeat(32));
        config
    };
    for config in [
        missing_handle,
        missing_revision,
        zero_revision,
        missing_digest,
        missing_enrollment_recipient_digest,
        zero_enrollment_recipient_digest,
        missing_wallet_recipient_digest,
        zero_wallet_recipient_digest,
        zero_digest,
    ] {
        assert_rejected(config);
    }
}
#[test]
fn enabled_pop_policy_rejects_test_marked_provider_handles() {
    let test_signer = {
        let mut config = valid_config();
        config.issuer_signer_handle = Some("software://sorafs/pop-credentials/test".to_owned());
        config
    };
    let test_enrollment_recipient = {
        let mut config = valid_config();
        config.enrollment_recipient_key_id = Some("kms://pop/mock/enrollment".to_owned());
        config
    };
    let test_wallet_wrapper = {
        let mut config = valid_config();
        config.wallet_wrapping_key_id = Some("kms://pop/fake/wallet".to_owned());
        config
    };
    let test_wallet_recipient = {
        let mut config = valid_config();
        config.wallet_recipient_key_id = Some("kms://pop/mock/wallet-recipient".to_owned());
        config
    };
    let test_registry = {
        let mut config = valid_config();
        config.runtime_provider_registry_handle =
            Some("runtime://pop/providers/placeholder".to_owned());
        config
    };
    for config in [
        test_signer,
        test_enrollment_recipient,
        test_wallet_recipient,
        test_wallet_wrapper,
        test_registry,
    ] {
        assert_rejected(config);
    }
}
