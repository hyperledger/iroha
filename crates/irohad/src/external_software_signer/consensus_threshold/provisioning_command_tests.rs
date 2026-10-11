//! Command custody I/O regression tests without inherited live runtime descriptors.

use super::*;
use std::{fs, io::Write as _, os::unix::fs::PermissionsExt as _};

#[test]
fn prepared_custody_retained_descriptor_is_nondestructive_and_rejects_shared_files() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("incumbent");
    let mut file = File::create(&path).unwrap();
    file.write_all(b"incumbent credential bytes").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let before = fs::read(&path).unwrap();
    assert_eq!(
        *read_retained_frame(File::open(&path).unwrap()).unwrap(),
        before
    );
    assert_eq!(fs::read(&path).unwrap(), before);
    fs::hard_link(&path, directory.path().join("alias")).unwrap();
    assert!(read_retained_frame(File::open(&path).unwrap()).is_err());
    assert_eq!(fs::read(&path).unwrap(), before);
    fs::remove_file(directory.path().join("alias")).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
    assert!(read_retained_frame(File::open(&path).unwrap()).is_err());
    assert_eq!(fs::read(&path).unwrap(), before);
}

#[test]
fn prepared_custody_publication_is_complete_exclusive_and_preserves_incumbent() {
    // Secure Directory intentionally rejects /tmp's writable ancestors.
    let root = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let parent = Directory::open(&fs::canonicalize(root.path()).unwrap()).unwrap();
    publish_generation(
        &parent,
        OsStr::new("generation-1"),
        b"credential-1",
        b"catalog-1",
        b"receipt-1",
    )
    .unwrap();
    assert_eq!(
        fs::read(root.path().join("generation-1").join(FILES[0])).unwrap(),
        b"credential-1"
    );
    assert_eq!(
        fs::metadata(root.path().join("generation-1").join(FILES[0]))
            .unwrap()
            .mode()
            & 0o7777,
        0o600
    );
    assert!(
        publish_generation(
            &parent,
            OsStr::new("generation-1"),
            b"credential-2",
            b"catalog-2",
            b"receipt-2"
        )
        .is_err()
    );
    assert_eq!(
        fs::read(root.path().join("generation-1").join(FILES[0])).unwrap(),
        b"credential-1"
    );
    assert_eq!(
        fs::read_dir(root.path()).unwrap().count(),
        1,
        "failed staging is removed"
    );
    publish_generation(
        &parent,
        OsStr::new("generation-2"),
        b"credential-2",
        b"catalog-2",
        b"receipt-2",
    )
    .unwrap();
    for (name, expected) in
        FILES
            .iter()
            .zip([b"credential-2".as_slice(), b"catalog-2", b"receipt-2"])
    {
        assert_eq!(
            fs::read(root.path().join("generation-2").join(name)).unwrap(),
            expected
        );
    }
    assert!(
        publish_generation(
            &parent,
            OsStr::new("../escaped"),
            b"credential-3",
            b"catalog-3",
            b"receipt-3"
        )
        .is_err()
    );
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 2);
}

#[test]
fn prepared_custody_cli_requires_external_pins_and_exposes_no_secret_argument() {
    use clap::CommandFactory as _;
    let help = Args::command().render_long_help().to_string();
    assert!(help.contains("--chain-id"));
    assert!(help.contains("--finality-allocated-bytes"));
    assert!(!help.contains("--trusted-context-id"));
    assert!(!help.contains("--anchor-height"));
    assert!(help.contains("--transition-id"));
    assert!(help.contains("--current-catalog"));
    assert!(help.contains("--credential-max-memory-bytes"));
    let command = Args::command();
    let bound = command
        .get_arguments()
        .find(|argument| argument.get_id() == "credential_max_memory_bytes")
        .unwrap()
        .clone();
    assert!(bound.is_required_set());
    let budget_command = clap::Command::new("budget").arg(bound);
    assert!(
        budget_command
            .clone()
            .try_get_matches_from(["budget"])
            .is_err()
    );
    assert!(
        budget_command
            .clone()
            .try_get_matches_from(["budget", "--credential-max-memory-bytes", "0"])
            .is_err()
    );
    assert!(
        budget_command
            .try_get_matches_from(["budget", "--credential-max-memory-bytes", "1"])
            .is_ok()
    );
    let budget = AllocationBudget::new(0);
    let original = budget.try_reserve_bytes(1).unwrap_err();
    let mapped = PreparationError::from(GlobalThresholdBeaconSessionError::Admission(
        original.clone(),
    ));
    assert!(
        matches!(mapped, PreparationError::Credential(RuntimeConsensusThresholdSignerCredentialErrorV1::Session(GlobalThresholdBeaconSessionError::Admission(actual))) if actual == original)
    );
    let proof_error = PreparationError::from(ValidatorCommitteeProvisioningEvidenceError::Session(
        GlobalThresholdBeaconSessionError::Admission(original.clone()),
    ));
    assert!(matches!(
        proof_error,
        PreparationError::Evidence(ValidatorCommitteeProvisioningEvidenceError::Session(
            GlobalThresholdBeaconSessionError::Admission(actual)
        )) if actual == original
    ));
    assert!(matches!(
        PreparationError::from(ValidatorCommitteeProvisioningEvidenceError::Invalid(
            "invalid signed evidence".to_owned()
        )),
        PreparationError::Evidence(ValidatorCommitteeProvisioningEvidenceError::Invalid(_))
    ));
    assert!(!help.contains("--private-key"));
    assert!(!help.contains("--seed"));
    assert!(Args::try_parse_from(["beacon-prepare-custody", "--output", "/tmp/new"]).is_err());
}

#[test]
fn provisioning_decoder_retains_original_scope_and_retries_unchanged_public_bytes() {
    use iroha_data_model::{
        isi::consensus_keys::{ThresholdKeyLifecycleActionV1, ThresholdKeyLifecycleCertificateV1},
        nexus::ValidatorCommitteeStatusV1,
        sumeragi::finality::{
            NativeFinalityArtifact, NativeFinalityDecodeError, NativeFinalityJournal,
            NativeFinalityLimits,
        },
    };
    // Codec-only envelope: these bytes establish no signature, finality or custody authority.
    let network = NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
        Hash::new(b"provisioning decoder source"),
    ));
    let artifact = NativeFinalityArtifact {
        block_wire: vec![1; 32],
    };
    let evidence = ValidatorCommitteeProvisioningEvidenceV1 {
        status: ValidatorCommitteeStatusV1 {
            network_id: network,
            target_epoch: 2,
            latest_finality: artifact.clone(),
            selected: None,
            pending_beacon_session: None,
        },
        finality_journal: NativeFinalityJournal {
            blocks: vec![artifact],
        },
        beacon_finalization: ThresholdKeyLifecycleCertificateV1 {
            version: 1,
            action: ThresholdKeyLifecycleActionV1::FinalizeGlobalBeaconKey,
            expected_active_session_id: None,
            effective_height: 2,
            network_id: network,
            roster_hash: [2; 32],
            committee_size: 4,
            quorum: 3,
            session_id: [3; 32],
            transcript_hash: [4; 32],
            public_state: vec![5; 32],
            signatures: Vec::new(),
        },
    };
    let bytes = norito::encode_canonical(&evidence).unwrap();
    let limits = NativeFinalityLimits {
        block_bytes: 1024 * 1024,
        journal_bytes: 4 * 1024 * 1024,
        block_count: 16,
        allocated_bytes: 64 * 1024 * 1024,
    };
    let error = norito::core::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
        || decode_provisioning_evidence(&bytes, limits),
    )
    .unwrap_err();
    let PreparationError::Journal(NativeJournalError::Decode(NativeFinalityDecodeError::Resource(
        original,
    ))) = error
    else {
        panic!("{error:?}");
    };
    assert_eq!(
        original.kind(),
        norito::core::DecodeAttemptErrorKind::EnclosingLimit
    );
    assert!(matches!(
        original.into_error().decode_resource_error(),
        Some(norito::core::DecodeResourceError::TotalAllocationExceeded { limit: 0, .. })
    ));
    assert_eq!(
        decode_provisioning_evidence(&bytes, limits).unwrap(),
        evidence
    );
    let mut trailing = bytes;
    trailing.push(0);
    assert!(matches!(
        decode_provisioning_evidence(&trailing, limits),
        Err(PreparationError::Journal(NativeJournalError::Decode(
            NativeFinalityDecodeError::Malformed(_)
        )))
    ));
}
