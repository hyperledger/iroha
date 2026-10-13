//! Per-seat beacon DKG command, phase-proof pipe and private custody tests.

use super::*;
use iroha_crypto::{Algorithm, Hash, HashOf};
use iroha_data_model::{NetworkId, block::BlockHeader};
use std::{fs::OpenOptions, os::unix::fs::PermissionsExt as _};

fn test_network() -> NetworkId {
    NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
        b"rotation-seat-command-network",
    )))
}

#[test]
fn rotation_rejects_unadmitted_evidence_before_opening_custody() {
    let mut limits = test_finality_limits();
    limits.allocated_bytes = 0;
    let proof = RotationProofArgs {
        selection_evidence: PathBuf::from("/must-not-open/unadmitted-evidence"),
        network_id: test_network(),
        chain_id: ChainId::from("rotation-phase-test"),
        finality_limits: limits,
        target_epoch: 2,
        transition_id: Hash::new(b"unproved-transition"),
    };
    assert!(matches!(
        read_verified_rotation_selection(
            &proof,
            &iroha_allocation::AllocationBudget::new(64 * 1024 * 1024),
        ),
        Err(Error::InvalidInput)
    ));
}

fn test_finality_limits() -> FinalityLimitsArgs {
    FinalityLimitsArgs {
        block_bytes: NATIVE_FINALITY_MAX_BLOCK_BYTES,
        journal_bytes: NATIVE_FINALITY_MAX_JOURNAL_BYTES,
        block_count: NATIVE_FINALITY_MAX_BLOCK_COUNT,
        allocated_bytes: 128 * 1024 * 1024,
    }
}

#[test]
fn finality_admission_rejects_zero_contradictory_and_over_protocol_limits() {
    assert!(test_finality_limits().checked().is_ok());
    let mut limits = test_finality_limits();
    limits.allocated_bytes = 0;
    assert!(matches!(limits.checked(), Err(Error::InvalidInput)));
    let mut limits = test_finality_limits();
    limits.journal_bytes = limits.block_bytes - 1;
    assert!(matches!(limits.checked(), Err(Error::InvalidInput)));
    let mut limits = test_finality_limits();
    limits.block_count = NATIVE_FINALITY_MAX_BLOCK_COUNT + 1;
    assert!(matches!(limits.checked(), Err(Error::InvalidInput)));
}

#[test]
fn rotation_phase_rejects_replay_gap_and_cutoff() {
    assert!(check_rotation_phase_height(10, 11, 14).is_ok());
    assert!(matches!(
        check_rotation_phase_height(11, 11, 14),
        Err(Error::Height)
    ));
    assert!(matches!(
        check_rotation_phase_height(11, 13, 14),
        Err(Error::Height)
    ));
    assert!(matches!(
        check_rotation_phase_height(13, 14, 14),
        Err(Error::Height)
    ));
    assert!(matches!(
        check_rotation_phase_height(u64::MAX, 0, u64::MAX),
        Err(Error::Height)
    ));
}

#[test]
fn claimed_journal_count_never_substitutes_for_actual_native_source() {
    use iroha_data_model::sumeragi::finality::NativeFinalityArtifact;
    let mut cursor = NativeJournalCursor::new(
        ChainId::from("rotation-phase-test"),
        test_network(),
        iroha_data_model::block::consensus::SumeragiRootScope::Global,
        test_finality_limits().checked().expect("limits"),
        &iroha_allocation::AllocationBudget::new(
            test_finality_limits().checked().unwrap().allocated_bytes,
        ),
    )
    .expect("cursor");
    let journal = NativeFinalityJournal {
        blocks: vec![
            NativeFinalityArtifact {
                block_wire: vec![0]
            };
            2
        ],
    };
    let mut height = 1;
    assert!(matches!(
        advance_phase_journal(&mut cursor, &journal, &mut height, 10),
        Err(Error::Journal(
            iroha_core::sumeragi::native_journal::NativeJournalError::Decode(
                iroha_data_model::sumeragi::finality::NativeFinalityDecodeError::Malformed(_)
            )
        ))
    ));
    assert_eq!(height, 1);
    assert!(cursor.tip().is_none());
    // An independently tracked phase clock cannot replace the retained native receipt.
    let mut height = 2;
    let journal = NativeFinalityJournal {
        blocks: vec![
            NativeFinalityArtifact {
                block_wire: vec![0]
            };
            3
        ],
    };
    assert!(matches!(
        advance_phase_journal(&mut cursor, &journal, &mut height, 10),
        Err(Error::Height)
    ));
    assert_eq!(height, 2);
    assert!(cursor.tip().is_none());
}

fn without_argument(args: &[String], name: &str) -> Vec<String> {
    let mut result = args.to_vec();
    let position = result
        .iter()
        .position(|arg| arg == name)
        .expect("argument exists");
    result.drain(position..position + 2);
    result
}

#[test]
fn rotation_seat_parser_requires_independent_pins_and_private_identity() {
    let transition = Hash::new(b"trusted-rotation-attempt").to_string();
    let base = vec![
        "beacon-bootstrap".to_owned(),
        "--credential-max-memory-bytes".to_owned(),
        (64 * 1024 * 1024).to_string(),
        "provision-rotation-seat".to_owned(),
        "--selection-evidence".to_owned(),
        "selection.norito".to_owned(),
        "--network-id".to_owned(),
        test_network().to_string(),
        "--chain-id".to_owned(),
        "rotation-test".to_owned(),
        "--target-epoch".to_owned(),
        "2".to_owned(),
        "--transition-id".to_owned(),
        transition,
    ];
    let mut seat = base.clone();
    seat.extend([
        "--signer-index".into(),
        "1".into(),
        "--key-fd".into(),
        "198".into(),
        "--public-fd".into(),
        "73".into(),
        "--finality-fd".into(),
        "74".into(),
        "--provider-handle".into(),
        "software://taira/global-beacon/rotation-seat-1".into(),
        "--provider-revision".into(),
        "1".into(),
        "--attempt-root".into(),
        "/tmp/owner-journal".into(),
    ]);
    assert!(Args::try_parse_from(&seat).is_ok());
    assert!(Args::try_parse_from(without_argument(&seat, "--chain-id")).is_err());
    let mut retired_pin = seat.clone();
    retired_pin.extend([
        "--trusted-context-id".into(),
        Hash::new(b"retired").to_string(),
    ]);
    assert!(Args::try_parse_from(retired_pin).is_err());
    let mut retired_height = seat.clone();
    retired_height.extend(["--anchor-height".into(), "10".into()]);
    assert!(Args::try_parse_from(retired_height).is_err());
    assert!(Args::try_parse_from(without_argument(&seat, "--key-fd")).is_err());
    let mut both_keys = seat.clone();
    both_keys.extend(["--config-fd".into(), "198".into()]);
    assert!(Args::try_parse_from(both_keys).is_err());
    let mut retired = seat.clone();
    retired[3] = "provision-rotation".into();
    assert!(Args::try_parse_from(retired).is_err());

    let mut assemble_dkg = base.clone();
    assemble_dkg[3] = "assemble-rotation-dkg".into();
    assemble_dkg.extend([
        "--public-session".into(),
        "session.norito".into(),
        "--phase-proof".into(),
        "phase-1.norito".into(),
        "--provider".into(),
        "seat-1-provider.json".into(),
        "--certificate-height".into(),
        "18".into(),
        "--output".into(),
        "rotation-bundle.json".into(),
    ]);
    assert!(Args::try_parse_from(&assemble_dkg).is_ok());
    assert!(Args::try_parse_from(without_argument(&assemble_dkg, "--provider")).is_err());

    let mut sign = base.clone();
    sign[3] = "sign-rotation".into();
    sign.extend([
        "--bundle".into(),
        "rotation-bundle.json".into(),
        "--signer-index".into(),
        "0".into(),
        "--key-fd".into(),
        "198".into(),
        "--output".into(),
        "signature.json".into(),
    ]);
    assert!(Args::try_parse_from(&sign).is_ok());
    assert!(Args::try_parse_from(without_argument(&sign, "--key-fd")).is_err());
}

#[test]
fn genesis_seat_parser_requires_signed_anchor_and_one_private_identity() {
    let base = vec![
        "beacon-bootstrap".to_owned(),
        "--credential-max-memory-bytes".to_owned(),
        (64 * 1024 * 1024).to_string(),
        "provision-genesis-seat".to_owned(),
        "--network-id".to_owned(),
        test_network().to_string(),
        "--chain-discriminant".to_owned(),
        "753".to_owned(),
        "--request".to_owned(),
        "request.json".to_owned(),
        "--genesis-manifest".to_owned(),
        "genesis-manifest.json".to_owned(),
        "--genesis-signed".to_owned(),
        "genesis.signed.nrt".to_owned(),
        "--genesis-public-key".to_owned(),
        "genesis.public-key".to_owned(),
        "--chain-id".to_owned(),
        "genesis-test".to_owned(),
    ];
    let mut seat = base.clone();
    seat.extend([
        "--signer-index".into(),
        "1".into(),
        "--key-fd".into(),
        "198".into(),
        "--public-fd".into(),
        "73".into(),
        "--finality-fd".into(),
        "74".into(),
        "--attempt-root".into(),
        "/tmp/owner-journal".into(),
    ]);
    assert!(Args::try_parse_from(&seat).is_ok());
    assert!(Args::try_parse_from(without_argument(&seat, "--genesis-signed")).is_err());
    assert!(Args::try_parse_from(without_argument(&seat, "--chain-id")).is_err());
    let mut retired = seat.clone();
    retired.extend(["--genesis-finality".into(), "fake-h1-qc.norito".into()]);
    assert!(Args::try_parse_from(retired).is_err());
    assert!(Args::try_parse_from(without_argument(&seat, "--key-fd")).is_err());
    let mut both = seat;
    both.extend(["--config-fd".into(), "198".into()]);
    assert!(Args::try_parse_from(both).is_err());
    let mut retired = base;
    retired[3] = "provision".into();
    assert!(Args::try_parse_from(retired).is_err());
}

#[test]
fn genesis_session_rejects_mutated_identity_under_same_attempt() {
    let network = test_network();
    let mut session = GlobalThresholdBeaconDkgSessionV1 {
        version: 1,
        network_id: network,
        session_id: genesis_seat::canonical_genesis_session_id(network),
        attempt_id: genesis_seat::canonical_genesis_attempt_id(network),
        authority_generation: 0,
        roster_hash: Hash::new(b"signed-genesis-roster").into(),
        committee_size: 4,
        threshold: 2,
        start_height: 1,
        commitments_end_height: 2,
        deliveries_end_height: 3,
        acceptances_end_height: 4,
    };
    assert!(genesis_seat::genesis_session_identity_is_canonical(
        network, session
    ));
    session.session_id = Hash::new(b"rerolled-session").into();
    assert!(!genesis_seat::genesis_session_identity_is_canonical(
        network, session
    ));
    session.session_id = genesis_seat::canonical_genesis_session_id(network);
    session.attempt_id = Hash::new(b"rerolled-attempt").into();
    assert!(!genesis_seat::genesis_session_identity_is_canonical(
        network, session
    ));
}

#[test]
fn genesis_public_assembly_requires_exact_proof_and_provider_inputs() {
    let base = vec![
        "beacon-bootstrap".to_owned(),
        "--credential-max-memory-bytes".to_owned(),
        (64 * 1024 * 1024).to_string(),
        "assemble-genesis-dkg".to_owned(),
        "--network-id".to_owned(),
        test_network().to_string(),
        "--chain-discriminant".to_owned(),
        "753".to_owned(),
        "--request".to_owned(),
        "request.json".to_owned(),
        "--genesis-manifest".to_owned(),
        "genesis-manifest.json".to_owned(),
        "--genesis-signed".to_owned(),
        "genesis.signed.nrt".to_owned(),
        "--genesis-public-key".to_owned(),
        "genesis.public-key".to_owned(),
        "--chain-id".to_owned(),
        "genesis-test".to_owned(),
        "--phase-proof".to_owned(),
        "phase-2.norito".to_owned(),
        "--public-session".to_owned(),
        "public-session.norito".to_owned(),
        "--provider".to_owned(),
        "seat-1-provider.json".to_owned(),
        "--certificate-height".to_owned(),
        "7".to_owned(),
        "--output".to_owned(),
        "public-bundle.json".to_owned(),
    ];
    assert!(Args::try_parse_from(&base).is_ok());
    assert!(Args::try_parse_from(without_argument(&base, "--phase-proof")).is_err());
    assert!(Args::try_parse_from(without_argument(&base, "--provider")).is_err());
}

#[test]
fn each_seat_credential_binds_exact_public_session_and_private_share() {
    for seats in [4_u16, 7] {
        let network = test_network();
        let session_id = Hash::new_from_chunks(&[b"daemon-seat-credential", &seats.to_be_bytes()]);
        let (public, components) = iroha_core::beacon::complete_beacon_dkg_fixture_for_seat_v1(
            network,
            session_id.into(),
            seats,
            seats,
        );
        let pool = test_credential_budget();
        let sealed =
            retain_public_session(&public, &pool).expect("original operation admits exact graph");
        let (digest, credential) = rotation_seat::encode_local_seat_credential(
            &sealed,
            seats,
            components,
            "software://taira/global-beacon/exact-seat",
            1,
            &pool,
        )
        .expect("exact private seat credential");
        assert!(!credential.is_empty());
        assert_eq!(
            digest,
            global_beacon_partial_signer_public_inventory_digest_v1(network, &[(&public, seats)],)
                .expect("exact public policy digest")
        );
    }
}

#[test]
fn rotation_config_descriptor_uses_only_exact_native_consensus_identity() {
    let _profile = iroha_data_model::account::address::ChainDiscriminantGuard::enter(369);
    let key = KeyPair::random_with_algorithm(Algorithm::BlsNormal);
    let network = test_network();
    let literal = Zeroizing::new(
        ExposedPrivateKey(key.private_key().clone())
            .try_to_multihash_string()
            .expect("canonical private key"),
    );
    let mut config = Zeroizing::new(format!(
        "chain = \"fc56984b-2be7-431d-840e-21514d1883f0\"\nchain_discriminant = 369\npublic_key = \"{}\"\nprivate_key = \"{}\"\n[genesis]\nexpected_hash = \"{}\"\n[torii.faucet]\nprivate_key_file = \"/must-not-read/faucet\"\n[torii.account_onboarding]\nprivate_key_file = \"/must-not-read/onboarding\"\n",
        key.public_key(),
        literal.as_str(),
        network
    ));
    assert_eq!(
        lifecycle_key_from_config(config.as_bytes(), &network)
            .expect("exact key")
            .public_key(),
        key.public_key()
    );
    let foreign =
        NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(b"foreign")));
    assert!(lifecycle_key_from_config(config.as_bytes(), &foreign).is_err());
    for (from, to) in [
        ("chain_discriminant = 369", "chain_discriminant = 1"),
        ("[genesis]", "extends = \"/must-not-read/base\"\n[genesis]"),
        (
            "[genesis]",
            "[genesis]\nexpected_hash_file = \"/must-not-read/identity\"",
        ),
    ] {
        let bad = Zeroizing::new(config.replace(from, to));
        assert!(lifecycle_key_from_config(bad.as_bytes(), &network).is_err());
    }
    let root = tempfile::Builder::new()
        .prefix(".beacon-config-test-")
        .tempdir_in(std::env::current_dir().expect("cwd"))
        .expect("private test root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private root");
    let path = fs::canonicalize(root.path()).expect("canonical root");
    for (name, bytes, success) in [
        ("valid", config.as_bytes(), true),
        ("malformed", b"not TOML".as_slice(), false),
    ] {
        let file_path = path.join(name);
        write_new(&file_path, bytes, true).expect("private config");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&file_path)
            .expect("open config");
        assert_eq!(load_lifecycle_config(file, &network).is_ok(), success);
        assert_eq!(fs::metadata(file_path).expect("truncated config").len(), 0);
    }
    config.zeroize();
}

#[test]
fn every_bootstrap_command_requires_one_explicit_positive_credential_limit() {
    let network = test_network().to_string();
    let transition = Hash::new(b"credential-command-bound").to_string();
    let genesis = [
        "--network-id",
        &network,
        "--chain-discriminant",
        "753",
        "--chain-id",
        "genesis-test",
        "--request",
        "request.json",
        "--genesis-manifest",
        "manifest.json",
        "--genesis-signed",
        "genesis.nrt",
        "--genesis-public-key",
        "genesis.key",
    ];
    let rotation = [
        "--selection-evidence",
        "selection.norito",
        "--network-id",
        &network,
        "--chain-id",
        "rotation-test",
        "--target-epoch",
        "2",
        "--transition-id",
        &transition,
    ];
    let genesis_install = [
        "--network-id",
        &network,
        "--chain-discriminant",
        "753",
        "--chain-id",
        "genesis-test",
        "--bundle",
        "bundle.json",
        "--output",
        "output.json",
    ];
    let cases: [(&str, &[&str], &[&str]); 8] = [
        (
            "provision-genesis-seat",
            &genesis,
            &[
                "--signer-index",
                "1",
                "--key-fd",
                "198",
                "--public-fd",
                "73",
                "--finality-fd",
                "74",
                "--attempt-root",
                "/owner-journal",
            ],
        ),
        (
            "assemble-genesis-dkg",
            &genesis,
            &[
                "--phase-proof",
                "phase.norito",
                "--public-session",
                "session.norito",
                "--provider",
                "provider.json",
                "--certificate-height",
                "5",
                "--output",
                "bundle.json",
            ],
        ),
        (
            "sign-genesis-install",
            &genesis_install,
            &["--signer-index", "0", "--key-fd", "198"],
        ),
        (
            "assemble-genesis-install",
            &genesis_install,
            &["--signature", "signature.json"],
        ),
        (
            "provision-rotation-seat",
            &rotation,
            &[
                "--signer-index",
                "1",
                "--key-fd",
                "198",
                "--public-fd",
                "73",
                "--finality-fd",
                "74",
                "--provider-handle",
                "software://taira/seat-1",
                "--provider-revision",
                "1",
                "--attempt-root",
                "/owner-journal",
            ],
        ),
        (
            "assemble-rotation-dkg",
            &rotation,
            &[
                "--phase-proof",
                "phase.norito",
                "--public-session",
                "session.norito",
                "--provider",
                "provider.json",
                "--certificate-height",
                "18",
                "--output",
                "bundle.json",
            ],
        ),
        (
            "sign-rotation",
            &rotation,
            &[
                "--bundle",
                "bundle.json",
                "--signer-index",
                "0",
                "--key-fd",
                "198",
                "--output",
                "signature.json",
            ],
        ),
        (
            "assemble-rotation",
            &rotation,
            &[
                "--bundle",
                "bundle.json",
                "--signature",
                "signature.json",
                "--output",
                "instruction.json",
            ],
        ),
    ];
    for (command, common, specific) in cases {
        let arguments = |limit: Option<&str>| {
            let mut args = vec!["beacon-bootstrap".to_owned()];
            if let Some(limit) = limit {
                args.extend(["--credential-max-memory-bytes".to_owned(), limit.to_owned()]);
            }
            args.push(command.to_owned());
            args.extend(
                common
                    .iter()
                    .chain(specific)
                    .map(|value| (*value).to_owned()),
            );
            args
        };
        let parsed = Args::try_parse_from(arguments(Some("1"))).expect("explicit command budget");
        assert_eq!(parsed.credential_max_memory_bytes.get(), 1, "{command}");
        assert!(Args::try_parse_from(arguments(None)).is_err(), "{command}");
        for invalid in ["0", "-1", "not-a-number", "18446744073709551616"] {
            assert!(
                Args::try_parse_from(arguments(Some(invalid))).is_err(),
                "{command}: {invalid}"
            );
        }
        let maximum = usize::MAX.to_string();
        assert_eq!(
            Args::try_parse_from(arguments(Some(&maximum)))
                .unwrap()
                .credential_max_memory_bytes
                .get(),
            usize::MAX,
            "parsing a declared finite cap must not allocate that capacity"
        );
    }
}

#[test]
fn bootstrap_session_refusal_retains_operation_source_and_last_credential_reader() {
    use iroha_core::beacon::credential::{
        ConsensusThresholdCredentialHeaderV1, ConsensusThresholdSecretScalarTripleV1,
        GLOBAL_BEACON_PARTIAL_SIGNER_SLOT_WIRE_ID_V1, GlobalBeaconCredentialEncodeErrorV1,
        PreparedGlobalBeaconCredentialV1,
    };
    const HANDLE: &str = "software://taira/global-beacon/original-pool";
    #[derive(norito::NoritoSerialize)]
    struct ShareShape<'a> {
        public_session: norito::core::PayloadRef<'a, GlobalThresholdBeaconKeySessionV1>,
        signer_index: u16,
        components: norito::core::PayloadRef<'a, ConsensusThresholdSecretScalarTripleV1>,
    }

    use iroha_allocation::{AllocationBudget, AllocationRefusal, release::ReleaseRegistration};
    use std::task::{Context, Waker};

    #[derive(norito::NoritoSerialize, norito::NoritoSchema)]
    #[norito_schema(
        name = "iroha_core::beacon::credential::RuntimeGlobalBeaconSignerCredentialWireV1",
        frame = "iroha.runtime_provider_broker.v1.consensus_threshold.global_beacon_signer_credential"
    )]
    struct CredentialShape<'a> {
        header: ConsensusThresholdCredentialHeaderV1,
        sessions: Vec<ShareShape<'a>>,
    }
    let (public, components) = iroha_core::beacon::complete_beacon_dkg_fixture_for_seat_v1(
        test_network(),
        Hash::new(b"bootstrap-original-credential-pool").into(),
        4,
        4,
    );
    let encoded = norito::encode_canonical(&public).unwrap();
    // This is the current canonical borrowed credential shape, with an inline
    // zero scalar triple for length only. The real producer below must reproduce
    // its exact length; no magic byte overhead or copied observed total is used.

    let digest =
        global_beacon_partial_signer_public_inventory_digest_v1(public.network_id, &[(&public, 4)])
            .unwrap();
    let zero = ConsensusThresholdSecretScalarTripleV1::from_zeroizing(Zeroizing::new([[0; 32]; 3]));
    let shape = CredentialShape {
        header: ConsensusThresholdCredentialHeaderV1::new(
            GLOBAL_BEACON_PARTIAL_SIGNER_SLOT_WIRE_ID_V1,
            public.network_id,
            HANDLE.to_owned(),
            1,
            digest,
        ),
        sessions: vec![ShareShape {
            public_session: norito::core::PayloadRef(&public),
            signer_index: 4,
            components: norito::core::PayloadRef(&zero),
        }],
    };
    let credential_bytes = norito::canonical_frame_len(&shape).unwrap();
    let output_demand = HANDLE.len().checked_add(credential_bytes).unwrap();
    drop(shape);
    let binding = GlobalThresholdBeaconSessionBindingV1 {
        network_id: public.network_id,
        session_id: public.session_id,
        roster_hash: public.roster_hash,
        transcript_hash: public.transcript_hash,
    };
    let total =
        iroha_core::beacon::global_threshold_beacon_session_allocation_bytes_v1(&public, &binding)
            .unwrap();
    let floor = ReleaseRegistration::allocation_layout().size();
    let pool = AllocationBudget::new(total + floor + output_demand);
    let mut prepaid = pool.try_reserve_bytes(floor).unwrap();
    let mut registration = ReleaseRegistration::from_reservation(&mut prepaid).unwrap();
    drop(prepaid);
    // Hold the exact independently derived output demand while testing the
    // session's original one-byte admission boundary in this same fixed pool.
    let output_reservation = pool.try_reserve_bytes(output_demand).unwrap();
    let blocker = pool.try_reserve_bytes(1).unwrap();
    let expected = pool.try_reserve_bytes(total).unwrap_err();
    let Err(Error::Session(GlobalThresholdBeaconSessionError::Admission(original))) =
        retain_public_session(&public, &pool)
    else {
        panic!("bootstrap must retain the original operation refusal instead of a crypto rejection")
    };
    assert_eq!(original, expected);
    assert_eq!(pool.reserved_bytes(), floor + output_demand + 1);
    let AllocationRefusal::Capacity { release, .. } = original else {
        panic!("held capacity source")
    };
    let mut context = Context::from_waker(Waker::noop());
    assert!(registration.poll_wait(&release, &mut context).is_pending());
    let unrelated = AllocationBudget::new(1);
    drop(unrelated.try_reserve_bytes(1).unwrap());
    assert!(registration.poll_wait(&release, &mut context).is_pending());
    drop(blocker);
    assert!(registration.poll_wait(&release, &mut context).is_ready());
    registration.cancel();
    let sealed = retain_public_session(&public, &pool).expect("same original source retry");
    assert!(sealed.belongs_to(&pool));
    assert_eq!(sealed.record(), &public);
    let retained = sealed.retained_allocation_bytes();
    let last = sealed.clone();
    assert!(last.ptr_eq(&sealed));
    drop(sealed);
    assert_eq!(pool.reserved_bytes(), floor + output_demand + retained);
    let expected_output = pool.try_reserve_bytes(output_demand).unwrap_err();
    let Err(GlobalBeaconCredentialEncodeErrorV1::Admission(actual_output)) =
        PreparedGlobalBeaconCredentialV1::new(
            public.network_id,
            HANDLE,
            1,
            digest,
            [(&last, 4)],
            &pool,
        )
    else {
        panic!("credential preparation must fund handle and complete frame before returning");
    };
    assert_eq!(actual_output, expected_output);
    assert_eq!(pool.reserved_bytes(), floor + output_demand + retained);
    assert!(last.belongs_to(&pool));
    drop(output_reservation);
    assert_eq!(pool.reserved_bytes(), floor + retained);
    let (policy_digest, credential) =
        rotation_seat::encode_local_seat_credential(&last, 4, components, HANDLE, 1, &pool)
            .expect("credential consumes only a borrowed sealed session");
    assert_eq!(credential.len(), credential_bytes);
    assert_eq!(policy_digest, global_beacon_partial_signer_public_inventory_digest_v1(
        public.network_id, &[(&public, 4)],
    ).unwrap());
    assert_eq!(
        pool.reserved_bytes(),
        floor + retained + credential.len(),
        "only the exact secret frame is additional; no duplicate session graph"
    );
    assert_eq!(norito::encode_canonical(&public).unwrap(), encoded);
    assert!(credential.belongs_to(&pool));
    drop(credential);
    assert_eq!(pool.reserved_bytes(), floor + retained);
    drop(last);
    assert_eq!(pool.reserved_bytes(), floor);
    let mut invalid = public.clone();
    invalid.version = 0;
    assert!(matches!(
        retain_public_session(&invalid, &pool),
        Err(Error::Crypto)
    ));
    assert_eq!(
        pool.reserved_bytes(),
        floor,
        "completed shape rejection consumes no original graph budget"
    );
    drop(registration);
    assert_eq!(pool.reserved_bytes(), 0);
}
