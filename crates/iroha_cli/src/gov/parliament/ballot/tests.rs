//! Tests for the timed-OVN ballot commands: parsing, owner-only files, seeded
//! record construction (golden) with Core validation, scheduling, relaying and
//! consensus-authenticated casting-context retrieval.

use std::{
    collections::BTreeMap,
    io::{Read as _, Write as _},
    net::TcpListener,
    path::Path,
    sync::mpsc,
    thread,
    time::Duration,
};

use clap::Parser as _;
use iroha_core_timed_ovn::evidence::TimedOvnLifecycleStateV1;
use iroha_core_timed_ovn::evidence::TimedOvnSessionPublicV1;
use iroha_core_timed_ovn::evidence::timed_ovn_parameter_hash_v1;
use iroha_core_timed_ovn::tle::ValidatedTleKeySessionV1;
use iroha_crypto::{
    Algorithm, Hash, HashOf, KeyPair, MerkleTree,
    threshold_bls::{
        AdaptiveThresholdBlsParameters, DasRenDealerSecret, ThresholdBlsSession, TleReleasePurpose,
    },
};
use iroha_data_model::{
    block::{
        BlockHeader,
        consensus::{ExecKv, ExecWitness},
    },
    governance::types::{BodyInstanceId, BodyInstanceStatusV1},
    parliament_casting::{
        PARLIAMENT_TIMED_OVN_CASTING_WITNESS_KEY_V1,
        ParliamentTimedOvnCastingContextMembershipProofV1,
        ParliamentTimedOvnCastingSnapshotCommitmentV1, ParliamentTimedOvnCastingWitnessProofV1,
    },
    sumeragi_finality::{
        SUMERAGI_LANE_STATE_WITNESS_KEY, SumeragiFinalityCheckpoint, SumeragiFinalityProof,
        SumeragiLaneStateCommitment,
    },
    testing::native_finality::NativeFinalityFixture,
};
use iroha_torii_shared::parliament_api::{
    PARLIAMENT_TIMED_OVN_CASTING_PROOF_VERSION_V1, ParliamentTimedOvnCastingProofRequestV1,
    ParliamentTimedOvnProgressProjectionV1,
};
use rand::{SeedableRng as _, rngs::StdRng};
use sha2::{Digest as _, Sha256};
use url::Url;

use super::{
    files::{BallotState, TimedOvnSeedV1},
    *,
};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const REGISTRATION_CLOSE_HEIGHT: u64 = 30;
const SURVIVOR_FREEZE_HEIGHT: u64 = 35;
const COMMITMENT_CLOSE_HEIGHT: u64 = 39;
const BALLOT_HEX: &str = "0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d";
const ATTEMPT_HEX: &str = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";

fn binding(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn seed(byte: u8) -> TimedOvnSeedV1 {
    TimedOvnSeedV1::from_bytes([byte; 32]).expect("non-zero seed fixture")
}

fn tle_fixture() -> ValidatedTleKeySessionV1 {
    tle_fixture_for_network(*fixture_network_id().as_bytes())
}

fn tle_fixture_for_network(network: [u8; 32]) -> ValidatedTleKeySessionV1 {
    let session =
        ThresholdBlsSession::<TleReleasePurpose>::new(network, binding(2), binding(3), 4, 2)
            .expect("threshold session");
    let parameters = AdaptiveThresholdBlsParameters::derive(&session).expect("parameters");
    let mut rng = StdRng::from_seed([31; 32]);
    let dealers = (1_u16..=3)
        .map(|index| {
            DasRenDealerSecret::generate_with_rng(&parameters, index, &mut rng)
                .expect("dealer")
                .1
        })
        .collect::<Vec<_>>();
    ValidatedTleKeySessionV1::from_qualified_dealers(session, &dealers, &[1, 2, 3], binding(4))
        .expect("TLE key session")
}

fn account(byte: u8) -> AccountId {
    let key =
        KeyPair::try_from_seed(vec![byte; 32], Algorithm::Ed25519).expect("account fixture key");
    AccountId::new(key.public_key().clone())
}

fn open_lifecycle(tle: &ValidatedTleKeySessionV1) -> TimedOvnLifecycleStateV1 {
    let session = TimedOvnSessionPublicV1 {
        network_id: tle.public_state().network_id,
        proposal_content_id: binding(10),
        governance_attempt_id: binding(11),
        body_instance_id: binding(12),
        ballot_attempt_id: binding(13),
        parameter_hash: timed_ovn_parameter_hash_v1(),
        tle_key_session_id: tle.public_state().key_session_id,
        tle_key_transcript_hash: tle.public_state().transcript_hash,
        tle_master_public_key: *tle.master_public_key().as_bytes(),
    };
    TimedOvnLifecycleStateV1::open_registration(session, 20, 40, tle).expect("open registration")
}

fn casting_context(
    lifecycle: &TimedOvnLifecycleStateV1,
    tle: &ValidatedTleKeySessionV1,
) -> ValidatedParliamentTimedOvnCastingContextArchiveV1 {
    let (finalized_height, phase, survivors, release_identity) = match lifecycle {
        TimedOvnLifecycleStateV1::Registered(_) => {
            (25, ParliamentTimedOvnCastingPhaseV1::Registered, None, None)
        }
        TimedOvnLifecycleStateV1::RegistrationClosed(_) => (
            32,
            ParliamentTimedOvnCastingPhaseV1::RegistrationClosed,
            None,
            None,
        ),
        TimedOvnLifecycleStateV1::SurvivorsFrozen(frozen) => (
            36,
            ParliamentTimedOvnCastingPhaseV1::SurvivorsFrozen,
            Some(frozen.survivor_participant_hashes().to_vec()),
            Some(*frozen.release_identity()),
        ),
        TimedOvnLifecycleStateV1::CorpusOpen(open) => (
            36,
            ParliamentTimedOvnCastingPhaseV1::SurvivorsFrozen,
            Some(open.frozen().survivor_participant_hashes().to_vec()),
            Some(*open.frozen().release_identity()),
        ),
        TimedOvnLifecycleStateV1::Sealed(_) | TimedOvnLifecycleStateV1::Released(_) => {
            panic!("test context must remain cast-capable")
        }
    };
    ParliamentTimedOvnCastingContextArchiveV1::try_from_parts_v1(
        finalized_height,
        phase,
        *lifecycle.session(),
        lifecycle
            .registration_opened_at_finalized_height()
            .expect("cast-capable registration-open height"),
        lifecycle.target_finalized_height(),
        tle.public_state().clone(),
        lifecycle.registration_records().to_vec(),
        survivors,
        release_identity,
    )
    .expect("casting context archive")
    .validate_v1()
    .expect("validated casting context")
}

fn fixture_ballot_id() -> BallotAttemptId {
    BallotAttemptId::new(binding(13))
}

fn native_fixture() -> NativeFinalityFixture {
    static GENESIS: std::sync::OnceLock<NativeFinalityFixture> = std::sync::OnceLock::new();
    GENESIS
        .get_or_init(|| NativeFinalityFixture::start("parliament-ballot-cli-test"))
        .clone()
}

fn fixture_network_id() -> NetworkId {
    native_fixture().network_id()
}

/// Three jurors registered through the CLI builder and accepted by Core.
struct RegisteredJurors {
    tle: ValidatedTleKeySessionV1,
    lifecycle: TimedOvnLifecycleStateV1,
    jurors: Vec<(AccountId, TimedOvnSeedV1)>,
    registration_records: Vec<Vec<u8>>,
}

fn register_jurors() -> RegisteredJurors {
    register_juror_count(3)
}

/// Register `count` jurors (accounts `0x51..`, seeds `0x61..`) in juror order.
fn register_juror_count(count: u8) -> RegisteredJurors {
    register_juror_count_with_tle(count, tle_fixture())
}

fn register_juror_count_with_tle(count: u8, tle: ValidatedTleKeySessionV1) -> RegisteredJurors {
    let mut lifecycle = open_lifecycle(&tle);
    let jurors = (0..count)
        .map(|offset| (account(0x51 + offset), seed(0x61 + offset)))
        .collect::<Vec<_>>();
    let mut registration_records = Vec::new();
    for (authority, juror_seed) in &jurors {
        let context = casting_context(&lifecycle, &tle);
        let plan = registration_from_seed(&context, authority, juror_seed)
            .expect("registration from seed");
        assert!(!plan.already_registered);
        assert_eq!(
            plan.governance_attempt_id,
            GovernanceAttemptId::new(binding(11))
        );
        assert_eq!(
            plan.participant_hash,
            parliament_ballot_participant_hash_v1(fixture_ballot_id(), authority)
        );
        lifecycle = lifecycle
            .register_participant(plan.participant_hash, plan.record.clone(), &tle)
            .expect("Core accepts the CLI registration record");
        let repeated =
            registration_from_seed(&casting_context(&lifecycle, &tle), authority, juror_seed)
                .expect("idempotent registration");
        assert!(repeated.already_registered);
        assert_eq!(repeated.record, plan.record);
        registration_records.push(plan.record);
    }
    RegisteredJurors {
        tle,
        lifecycle,
        jurors,
        registration_records,
    }
}

fn digest_hex(records: &[Vec<u8>]) -> String {
    let mut hasher = Sha256::new();
    for record in records {
        hasher.update(record);
    }
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// Command parsing
// ---------------------------------------------------------------------------

#[derive(clap::Parser, Debug)]
struct BallotFixture {
    #[command(subcommand)]
    command: BallotCommand,
}

#[derive(clap::Parser, Debug)]
struct ParliamentFixture {
    #[command(subcommand)]
    command: super::super::ParliamentCommand,
}

fn parse(args: &[&str]) -> Result<BallotCommand, clap::Error> {
    BallotFixture::try_parse_from(std::iter::once("ballot").chain(args.iter().copied()))
        .map(|fixture| fixture.command)
}

#[test]
fn ballot_commands_parse_their_flags() {
    let register = parse(&[
        "register",
        "--ballot-attempt-id",
        BALLOT_HEX,
        "--key-file",
        "/keys/juror.key",
        "--trusted-checkpoint-file",
        "/trust/checkpoint.nrt",
    ])
    .expect("register parses");
    let BallotCommand::Register(register) = register else {
        panic!("expected register")
    };
    assert_eq!(register.ballot_attempt_id.to_hex(), BALLOT_HEX);
    assert_eq!(register.files.key_file, Path::new("/keys/juror.key"));
    assert_eq!(
        register.files.state.trusted_checkpoint_file.as_deref(),
        Some(Path::new("/trust/checkpoint.nrt"))
    );
    assert_eq!(register.files.state.state_file, None);

    for (label, expected) in [
        ("approve", BallotChoiceArg::Approve),
        ("reject", BallotChoiceArg::Reject),
        ("abstain", BallotChoiceArg::Abstain),
    ] {
        let cast = parse(&[
            "cast",
            "--ballot-attempt-id",
            BALLOT_HEX,
            "--key-file",
            "/keys/juror.key",
            "--choice",
            label,
            "--record-out",
            "/tmp/record.hex",
            "--wait-secs",
            "30",
        ])
        .expect("cast parses");
        let BallotCommand::Cast(cast) = cast else {
            panic!("expected cast")
        };
        assert_eq!(cast.choice, expected);
        assert_eq!(cast.wait_secs, 30);
        assert_eq!(
            cast.record_out.as_deref(),
            Some(Path::new("/tmp/record.hex"))
        );
        assert_eq!(
            BallotChoiceArg::from_label(expected.label()),
            Some(expected)
        );
    }

    let Ok(BallotCommand::Dropout(bare_dropout)) =
        parse(&["dropout", "--ballot-attempt-id", BALLOT_HEX])
    else {
        panic!("expected a bare dropout")
    };
    assert_eq!(bare_dropout.key_file, None);
    assert_eq!(bare_dropout.state.state_file, None);
    let Ok(BallotCommand::Dropout(dropout)) = parse(&[
        "dropout",
        "--ballot-attempt-id",
        BALLOT_HEX,
        "--key-file",
        "/keys/juror.key",
        "--state-file",
        "/keys/juror.state.nrt",
    ]) else {
        panic!("expected a dropout with local files")
    };
    assert_eq!(
        dropout.key_file.as_deref(),
        Some(Path::new("/keys/juror.key"))
    );
    assert_eq!(
        dropout.state.state_file.as_deref(),
        Some(Path::new("/keys/juror.state.nrt"))
    );
    let Ok(BallotCommand::Status(by_ballot)) = parse(&[
        "status",
        "--ballot-attempt-id",
        BALLOT_HEX,
        "--key-file",
        "/keys/juror.key",
        "--state-file",
        "/keys/juror.state.nrt",
    ]) else {
        panic!("expected status by ballot")
    };
    assert_eq!(by_ballot.governance_attempt_id, None);
    assert_eq!(by_ballot.ballot_attempt_id, Some(fixture_ballot_id()));
    assert_eq!(
        by_ballot.key_file.as_deref(),
        Some(Path::new("/keys/juror.key"))
    );
    let relay = parse(&[
        "relay",
        "--ballot-attempt-id",
        BALLOT_HEX,
        "--record",
        "/tmp/a.hex",
        "--record",
        "/tmp/b.hex",
    ])
    .expect("relay parses");
    let BallotCommand::Relay(relay) = relay else {
        panic!("expected relay")
    };
    assert_eq!(relay.records.len(), 2);
    assert!(matches!(
        parse(&["status", "--governance-attempt-id", ATTEMPT_HEX]),
        Ok(BallotCommand::Status(StatusArgs {
            ballot_attempt_id: None,
            ..
        }))
    ));
    assert!(
        parse(&["anchor", "--height", "12"]).is_err(),
        "the finality-anchor lookup is retired"
    );

    let nested = ParliamentFixture::try_parse_from([
        "parliament",
        "ballot",
        "status",
        "--governance-attempt-id",
        ATTEMPT_HEX,
        "--ballot-attempt-id",
        BALLOT_HEX,
    ])
    .expect("nested ballot command parses");
    assert!(matches!(
        nested.command,
        super::super::ParliamentCommand::Ballot(BallotCommand::Status(_))
    ));
}

#[test]
fn ballot_commands_reject_invalid_flags() {
    let cast = |choice: &str| {
        parse(&[
            "cast",
            "--ballot-attempt-id",
            BALLOT_HEX,
            "--key-file",
            "/k",
            "--choice",
            choice,
        ])
    };
    assert!(cast("aye").is_err(), "wire names are not CLI choices");
    assert!(cast("APPROVE").is_err());
    assert!(
        parse(&[
            "cast",
            "--ballot-attempt-id",
            BALLOT_HEX,
            "--key-file",
            "/k"
        ])
        .is_err(),
        "the choice is mandatory"
    );
    assert!(
        parse(&["register", "--ballot-attempt-id", BALLOT_HEX]).is_err(),
        "the key file is mandatory"
    );
    assert!(
        parse(&[
            "register",
            "--ballot-attempt-id",
            BALLOT_HEX,
            "--key-file",
            "/k",
            "--trusted-checkpoint-height",
            "5",
        ])
        .is_err(),
        "retired scalar checkpoint flags are rejected"
    );
    for invalid_context in [
        "0e".repeat(32),
        "0F".repeat(32),
        "00".repeat(32),
        "0f".repeat(31),
    ] {
        assert!(
            parse(&[
                "register",
                "--ballot-attempt-id",
                BALLOT_HEX,
                "--key-file",
                "/k",
                "--trusted-checkpoint-height",
                "5",
                "--trusted-checkpoint-context-id",
                &invalid_context,
            ])
            .is_err(),
            "non-canonical context id must fail: {invalid_context}"
        );
    }
    assert!(parse(&["relay", "--ballot-attempt-id", BALLOT_HEX]).is_err());
    assert!(parse(&["dropout", "--ballot-attempt-id", &"00".repeat(32)]).is_err());
    assert!(
        parse(&["status"]).is_err(),
        "status names an attempt or a ballot"
    );
    assert!(
        parse(&["status", "--key-file", "/k"]).is_err(),
        "local files alone do not name a ballot"
    );
    assert!(
        parse(&[
            "dropout",
            "--ballot-attempt-id",
            BALLOT_HEX,
            "--trusted-checkpoint-height",
            "5",
        ])
        .is_err(),
        "dropout rejects retired scalar checkpoint flags"
    );
    assert!(
        parse(&[
            "status",
            "--ballot-attempt-id",
            BALLOT_HEX,
            "--trusted-checkpoint-height",
            "5",
            "--trusted-checkpoint-context-id",
            &"0f".repeat(32),
        ])
        .is_err(),
        "status never initializes a state file"
    );
    assert!(parse(&["anchor", "--height", "0"]).is_err());
    assert!(
        parse(&[
            "register",
            "--ballot-attempt-id",
            BALLOT_HEX,
            "--seed",
            "00"
        ])
        .is_err(),
        "secrets are never accepted on argv"
    );
}

// ---------------------------------------------------------------------------
// Owner-only files
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("set mode");
}

#[cfg(unix)]
fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::symlink_metadata(path)
        .expect("stat")
        .permissions()
        .mode()
        & 0o7777
}

#[cfg(unix)]
#[test]
fn key_file_is_generated_owner_only_and_reloaded() {
    let directory = tempfile::tempdir().expect("key directory");
    let path = directory.path().join("juror.key");
    let (created_seed, created) = files::load_or_create_key_file(&path).expect("create key");
    assert!(created);
    assert_eq!(mode_of(&path), 0o600);
    let (reloaded, created_again) = files::load_or_create_key_file(&path).expect("reload key");
    assert!(!created_again);
    assert_eq!(reloaded.as_bytes(), created_seed.as_bytes());
    assert_eq!(
        files::load_key_file(&path).expect("load key").as_bytes(),
        created_seed.as_bytes()
    );
    let debug = format!("{reloaded:?}");
    assert!(debug.contains("redacted"));
    assert!(!debug.contains(&hex::encode(reloaded.as_bytes())));
    let staged = std::fs::read_dir(directory.path())
        .expect("list key directory")
        .count();
    assert_eq!(staged, 1, "no staging file may remain next to the key");

    set_mode(&path, 0o400);
    assert!(
        files::load_key_file(&path).is_ok(),
        "read-only owner mode is accepted"
    );
    let other = files::load_or_create_key_file(&directory.path().join("other.key"))
        .expect("second key")
        .0;
    assert_ne!(other.as_bytes(), created_seed.as_bytes());
}

#[cfg(unix)]
#[test]
fn key_file_with_loose_permissions_or_indirection_is_refused() {
    let directory = tempfile::tempdir().expect("key directory");
    let path = directory.path().join("juror.key");
    files::load_or_create_key_file(&path).expect("create key");
    for loose in [0o644, 0o640, 0o604, 0o660, 0o700, 0o200] {
        set_mode(&path, loose);
        let error = files::load_key_file(&path).expect_err("loose mode must be refused");
        assert!(
            format!("{error:#}").contains("owner-only"),
            "mode {loose:o}: {error:#}"
        );
        assert!(
            files::load_or_create_key_file(&path).is_err(),
            "an existing loose key file must not be replaced"
        );
    }
    set_mode(&path, 0o600);

    let link = directory.path().join("link.key");
    std::os::unix::fs::symlink(&path, &link).expect("symlink");
    assert!(files::load_key_file(&link).is_err(), "symlinks are refused");
    assert!(files::load_or_create_key_file(&link).is_err());

    let hard = directory.path().join("hard.key");
    std::fs::hard_link(&path, &hard).expect("hard link");
    assert!(
        files::load_key_file(&path).is_err(),
        "hard links are refused"
    );
    std::fs::remove_file(&hard).expect("remove hard link");
    assert!(files::load_key_file(&path).is_ok());

    let garbage = directory.path().join("garbage.key");
    std::fs::write(&garbage, b"not a key-file frame").expect("write garbage");
    set_mode(&garbage, 0o600);
    assert!(files::load_key_file(&garbage).is_err());
    let empty = directory.path().join("empty.key");
    std::fs::write(&empty, b"").expect("write empty");
    set_mode(&empty, 0o600);
    assert!(files::load_key_file(&empty).is_err());
    assert!(files::load_key_file(&directory.path().join("missing.key")).is_err());
    assert!(TimedOvnSeedV1::from_bytes([0; 32]).is_err());
}

fn checkpoint(height: u64, branch: u8) -> SumeragiFinalityCheckpoint {
    let mut fixture = native_fixture();
    for _ in 2..=height {
        let mut header = fixture.next_header();
        header.creation_time_ms += u64::from(branch);
        let block = fixture.block_with_submitted_work(header);
        fixture.certify(block);
    }
    fixture.checkpoint()
}

#[cfg(unix)]
#[test]
fn state_file_pins_network_and_promotes_checkpoints() {
    let directory = tempfile::tempdir().expect("state directory");
    let key = directory.path().join("juror.key");
    let path = files::default_state_path(&key);
    assert_eq!(path, directory.path().join("juror.key.state.nrt"));
    let network = *fixture_network_id().as_bytes();

    let missing = BallotState::open(&path, network, None).expect_err("uninitialized state");
    assert!(format!("{missing:#}").contains("--trusted-checkpoint-file"));
    assert!(
        BallotState::open(&path, binding(0x23), Some(checkpoint(3, 5))).is_err(),
        "an independently selected checkpoint must belong to the configured network"
    );
    assert!(!path.exists(), "invalid anchors create no file");

    let mut state =
        BallotState::open(&path, network, Some(checkpoint(3, 5))).expect("initialize state");
    assert_eq!(mode_of(&path), 0o600);
    assert_eq!(state.checkpoint(), checkpoint(3, 5));
    assert!(
        BallotState::open(&path, network, Some(checkpoint(3, 5))).is_err(),
        "an existing state file keeps its own anchor"
    );
    assert!(
        BallotState::open(&path, binding(0x23), None).is_err(),
        "a state file belongs to one network"
    );

    state
        .promote(checkpoint(3, 5))
        .expect("same checkpoint is a no-op");
    assert!(state.promote(checkpoint(2, 6)).is_err(), "no regression");
    assert!(
        state.promote(checkpoint(3, 7)).is_err(),
        "no fork at one height"
    );
    state.promote(checkpoint(9, 5)).expect("promote");
    let mut reloaded = BallotState::open(&path, network, None).expect("reload");
    assert_eq!(reloaded.checkpoint(), checkpoint(9, 5));
    assert_eq!(mode_of(&path), 0o600);
    assert_eq!(
        mode_of(&directory.path().join("juror.key.state.nrt.lock")),
        0o600,
        "promotion serializes on an owner-only lock file"
    );

    set_mode(&path, 0o644);
    assert!(
        BallotState::open(&path, network, None).is_err(),
        "a loose state file is refused"
    );
    assert!(
        reloaded.promote(checkpoint(12, 9)).is_err(),
        "a state file whose custody changed is not overwritten"
    );
    set_mode(&path, 0o600);
    std::fs::write(&path, format!("{{\"version\":1,\"network_id\":\"{}\",\"checkpoint_height\":9,\"checkpoint_context_id\":\"{}\"}}", hex::encode(network), "07".repeat(32)))
        .expect("write retired scalar layout");
    set_mode(&path, 0o600);
    assert!(BallotState::open(&path, network, None).is_err());
}

#[cfg(unix)]
#[test]
fn checkpoint_input_requires_complete_canonical_authenticated_material_and_private_custody() {
    let directory = tempfile::tempdir().expect("checkpoint directory");
    let path = directory.path().join("checkpoint.nrt");
    let checkpoint = checkpoint(3, 5);
    let canonical = checkpoint.encode_canonical().expect("canonical checkpoint");
    std::fs::write(&path, &canonical).expect("checkpoint input");
    set_mode(&path, 0o600);
    assert_eq!(files::load_checkpoint(&path).expect("import"), checkpoint);

    let mut trailing = canonical.clone();
    trailing.push(0);
    std::fs::write(&path, trailing).expect("noncanonical checkpoint");
    assert!(files::load_checkpoint(&path).is_err());

    let mut forged = canonical.clone();
    let wire = &checkpoint.tip().block_wire;
    let offset = forged
        .windows(wire.len())
        .position(|candidate| candidate == wire)
        .expect("exact tip wire is retained");
    forged[offset] ^= 1;
    std::fs::write(&path, forged).expect("forged tip");
    assert!(files::load_checkpoint(&path).is_err());

    std::fs::write(&path, &canonical).expect("restore input");
    set_mode(&path, 0o644);
    assert!(files::load_checkpoint(&path).is_err());
    set_mode(&path, 0o600);
    let symlink = directory.path().join("checkpoint-link.nrt");
    std::os::unix::fs::symlink(&path, &symlink).expect("symlink");
    assert!(files::load_checkpoint(&symlink).is_err());

    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("open input")
        .set_len(iroha_data_model::sumeragi_finality::MAX_FINALITY_CHECKPOINT_BYTES as u64 + 1)
        .expect("oversized sparse input");
    assert!(files::load_checkpoint(&path).is_err());
}

#[cfg(unix)]
#[test]
fn state_promotion_accepts_another_exact_quorum_for_the_same_certified_decision() {
    use iroha_data_model::{
        block::{CommitCertificate, decode_framed_signed_block},
        sumeragi_finality::SumeragiFinalityVerifier,
    };
    use iroha_sumeragi::{
        message::Qc,
        types::{AggregateSignature, Bitmap},
    };

    let checkpoint = checkpoint(3, 5);
    let mut proof = checkpoint.tip().clone();
    let mut block = decode_framed_signed_block(&proof.block_wire).expect("certified block");
    let certificate = block.commit_certificate().expect("certificate");
    let mut qc: Qc = norito::decode_canonical(certificate.commit_qc()).expect("native QC");
    let mut keys: Vec<_> = (1..=4)
        .map(|seed| KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal))
        .collect();
    keys.sort_by_key(|key| key.public_key().try_to_bytes().unwrap().1.to_vec());
    qc.signers = Bitmap::from_indices(4, [1, 2, 3]).expect("another exact quorum");
    let signatures: Vec<_> = keys[1..]
        .iter()
        .map(|key| {
            iroha_crypto::bls::consensus::sign_preimage(key.private_key(), &qc.preimage()).unwrap()
        })
        .collect();
    qc.agg_sig = AggregateSignature(iroha_crypto::bls::consensus::aggregate(&signatures).unwrap());
    let replacement = CommitCertificate::from_untrusted_parts(
        certificate.consensus_header().to_vec(),
        norito::encode_canonical(&qc).unwrap(),
        certificate.result_preimage().to_vec(),
        certificate.availability().to_vec(),
    );
    block.set_commit_certificate(Some(replacement));
    proof.block_wire = block.encode_wire().unwrap();
    let verifier = SumeragiFinalityVerifier::from_trusted_checkpoint(
        &checkpoint,
        &checkpoint.network_id(),
        checkpoint.chain_id(),
    )
    .unwrap();
    let alternate = verifier
        .export_checkpoint(&proof)
        .expect("equivalent certified tip");
    assert_ne!(checkpoint, alternate);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state.nrt");
    let mut state = BallotState::open(
        &path,
        *checkpoint.network_id().as_bytes(),
        Some(checkpoint.clone()),
    )
    .unwrap();
    state
        .promote(alternate)
        .expect("same decision remains trusted");
    assert_eq!(BallotState::load(&path).unwrap().checkpoint(), checkpoint);
}

#[test]
fn public_records_round_trip_and_never_change() {
    let directory = tempfile::tempdir().expect("record directory");
    let path = directory.path().join("record.hex");
    let record = vec![0xAB_u8; TIMED_OVN_BALLOT_RECORD_BYTES_V1];
    files::write_public_record(&path, &record).expect("write record");
    assert_eq!(
        files::read_public_record(&path, TIMED_OVN_BALLOT_RECORD_BYTES_V1).expect("read record"),
        record
    );
    files::write_public_record(&path, &record).expect("identical rewrite");
    let mut different = record.clone();
    different[0] ^= 1;
    assert!(files::write_public_record(&path, &different).is_err());
    assert!(
        files::read_public_record(&path, 16).is_err(),
        "width is exact"
    );
    let upper = directory.path().join("upper.hex");
    std::fs::write(&upper, hex::encode_upper(&record)).expect("write upper");
    assert!(files::read_public_record(&upper, TIMED_OVN_BALLOT_RECORD_BYTES_V1).is_err());
}

// ---------------------------------------------------------------------------
// Seeded records (golden) and Core validation
// ---------------------------------------------------------------------------

#[test]
fn keyed_rng_is_deterministic_and_domain_separated() {
    let juror_seed = seed(0x44);
    let mut first = registration_rng(&juror_seed, &binding(1), &binding(2));
    let mut second = registration_rng(&juror_seed, &binding(1), &binding(2));
    let mut other_participant = registration_rng(&juror_seed, &binding(1), &binding(3));
    let mut ballot = ballot_rng(
        &juror_seed,
        &binding(1),
        &binding(2),
        &binding(4),
        &binding(5),
        TimedOvnChoiceV1::Aye,
    );
    let mut ballot_other_choice = ballot_rng(
        &juror_seed,
        &binding(1),
        &binding(2),
        &binding(4),
        &binding(5),
        TimedOvnChoiceV1::Nay,
    );
    let draw = |rng: &mut KeyedBlake3Rng| {
        let mut out = [0_u8; 80];
        rng.try_fill_bytes(&mut out).expect("draw");
        out
    };
    let first_draw = draw(&mut first);
    assert_eq!(first_draw, draw(&mut second));
    assert_ne!(first_draw, draw(&mut other_participant));
    let ballot_draw = draw(&mut ballot);
    assert_ne!(first_draw, ballot_draw);
    assert_ne!(ballot_draw, draw(&mut ballot_other_choice));
    assert!(first_draw.iter().any(|byte| *byte != 0));
    let mut split = registration_rng(&juror_seed, &binding(1), &binding(2));
    let mut pieces = [0_u8; 80];
    let (left, right) = pieces.split_at_mut(7);
    split.try_fill_bytes(left).expect("left draw");
    split.try_fill_bytes(right).expect("right draw");
    assert_eq!(pieces, first_draw, "the stream is independent of chunking");
}

/// Golden SHA-256 over the three seeded registration records, in juror order.
const GOLDEN_REGISTRATION_DIGEST: &str =
    "a2445e7650480f36ff6677fe55de29ca0c8e5bd25c7d52f0f280d3b664c12a5f";
/// Golden SHA-256 over the three seeded masked ballots, in survivor order.
const GOLDEN_BALLOT_DIGEST: &str =
    "8ef15b075abb48d24e88ae5291dbf1300e17c3b9aa3b3fe744f739d9dfccc3a6";

#[test]
fn seeded_records_match_golden_and_pass_core_validation() {
    let RegisteredJurors {
        tle,
        lifecycle,
        jurors,
        registration_records,
    } = register_juror_count_with_tle(3, tle_fixture_for_network(binding(1)));
    let registration_digest = digest_hex(&registration_records);
    let lifecycle = lifecycle
        .close_registration(&tle)
        .expect("close registration")
        .freeze_survivors(&tle)
        .expect("freeze survivors");
    let frozen = casting_context(&lifecycle, &tle);
    let choices = [
        BallotChoiceArg::Approve,
        BallotChoiceArg::Reject,
        BallotChoiceArg::Abstain,
    ];
    let mut by_seat = BTreeMap::new();
    for ((authority, juror_seed), choice) in jurors.iter().zip(choices) {
        let seat = survivor_seat(&frozen, authority).expect("survivor seat");
        assert_eq!(seat.survivor_count, 3);
        let record = ballot_from_seed(&frozen, authority, juror_seed, choice).expect("ballot");
        assert_eq!(record.len(), TIMED_OVN_BALLOT_RECORD_BYTES_V1);
        assert_eq!(
            record,
            ballot_from_seed(&frozen, authority, juror_seed, choice).expect("repeat ballot"),
            "ballots are deterministic per seed, ballot and choice"
        );
        if choice != BallotChoiceArg::Abstain {
            assert_ne!(
                record,
                ballot_from_seed(&frozen, authority, juror_seed, BallotChoiceArg::Abstain)
                    .expect("other-choice ballot"),
                "each choice draws its own proof randomness"
            );
        }
        assert!(by_seat.insert(seat.index, record).is_none());
    }
    let ballots = by_seat.values().cloned().collect::<Vec<_>>();
    let ballot_digest = digest_hex(&ballots);
    assert_eq!(
        (registration_digest.as_str(), ballot_digest.as_str()),
        (GOLDEN_REGISTRATION_DIGEST, GOLDEN_BALLOT_DIGEST),
        "seeded timed-OVN records changed"
    );

    // Relay-style chunking through Core: one record, then the rest.
    let indexed = index_relay_records(&frozen, ballots.clone()).expect("verified records");
    let first_chunk =
        relay_chunk(0, &BTreeMap::from([(0, indexed[&0].clone())])).expect("first chunk");
    let corpus_open = lifecycle
        .seal_ballots(first_chunk, &tle)
        .expect("Core accepts the first CLI ballot chunk");
    assert!(matches!(
        corpus_open,
        TimedOvnLifecycleStateV1::CorpusOpen(_)
    ));
    assert_eq!(corpus_open.accepted_ballot_prefix_count(), Some(1));
    let open_context = casting_context(&corpus_open, &tle);
    for (authority, juror_seed) in &jurors {
        let seat = survivor_seat(&open_context, authority).expect("seat while corpus open");
        let choice = choices[jurors
            .iter()
            .position(|(candidate, _)| candidate == authority)
            .expect("juror position")];
        assert_eq!(
            ballot_from_seed(&open_context, authority, juror_seed, choice).expect("ballot"),
            by_seat[&seat.index],
            "a corpus-open context rebuilds the same ballot"
        );
    }
    let rest = relay_chunk(1, &indexed).expect("remaining chunk");
    assert_eq!(rest.len(), 2);
    let sealed = corpus_open
        .seal_ballots(rest, &tle)
        .expect("Core accepts the remaining CLI ballots");
    assert!(matches!(sealed, TimedOvnLifecycleStateV1::Sealed(_)));
    assert_eq!(sealed.accepted_ballot_prefix_count(), Some(3));
}

#[test]
fn registration_and_ballot_builders_fail_closed() {
    let RegisteredJurors {
        tle,
        lifecycle,
        jurors,
        ..
    } = register_juror_count(4);
    let registered = casting_context(&lifecycle, &tle);
    let (authority, juror_seed) = &jurors[0];

    // A different seed cannot re-register the same account.
    let conflict = registration_from_seed(&registered, authority, &seed(0x99))
        .expect_err("conflicting registration");
    assert!(format!("{conflict:#}").contains("key file does not hold the seed"));
    assert!(
        ballot_from_seed(&registered, authority, juror_seed, BallotChoiceArg::Approve).is_err(),
        "no ballots before the survivor freeze"
    );

    let dropped_hash = parliament_ballot_participant_hash_v1(fixture_ballot_id(), &jurors[1].0);
    let closed = lifecycle
        .close_registration(&tle)
        .expect("close registration");
    let closed_context = casting_context(&closed, &tle);
    assert!(
        registration_from_seed(&closed_context, &account(0x5A), &seed(0x6A)).is_err(),
        "no registration after close"
    );
    assert_eq!(
        dropout_precheck(&closed_context, &jurors[1].0).expect("registered juror may drop out"),
        GovernanceAttemptId::new(binding(11))
    );
    assert!(
        dropout_precheck(&closed_context, &account(0x5A)).is_err(),
        "an unregistered account cannot drop out"
    );
    assert!(
        dropout_precheck(&registered, &jurors[1].0).is_err(),
        "dropouts wait for registration to close"
    );
    let frozen = closed
        .record_dropout(dropped_hash, &tle)
        .expect("Core records the dropout")
        .freeze_survivors(&tle)
        .expect("freeze survivors");
    let frozen_context = casting_context(&frozen, &tle);
    assert!(dropout_precheck(&frozen_context, &jurors[0].0).is_err());
    let dropped = survivor_seat(&frozen_context, &jurors[1].0).expect_err("dropped out");
    assert!(format!("{dropped:#}").contains("not a frozen survivor"));
    assert!(
        ballot_from_seed(
            &frozen_context,
            &jurors[1].0,
            &jurors[1].1,
            BallotChoiceArg::Approve
        )
        .is_err()
    );
    let seat = survivor_seat(&frozen_context, authority).expect("remaining survivor");
    assert_eq!(seat.survivor_count, 3);
    let wrong_seed = ballot_from_seed(
        &frozen_context,
        authority,
        &seed(0x99),
        BallotChoiceArg::Reject,
    )
    .expect_err("wrong key file");
    assert!(format!("{wrong_seed:#}").contains("key file does not hold the seed"));
    assert!(
        survivor_seat(&frozen_context, &account(0x5A)).is_err(),
        "a stranger has no seat"
    );
}

#[test]
fn relay_records_are_verified_indexed_and_chunked() {
    let RegisteredJurors {
        tle,
        lifecycle,
        jurors,
        ..
    } = register_jurors();
    let lifecycle = lifecycle
        .close_registration(&tle)
        .and_then(|closed| closed.freeze_survivors(&tle))
        .expect("freeze survivors");
    let frozen = casting_context(&lifecycle, &tle);
    let records = jurors
        .iter()
        .map(|(authority, juror_seed)| {
            ballot_from_seed(&frozen, authority, juror_seed, BallotChoiceArg::Approve)
                .expect("ballot")
        })
        .collect::<Vec<_>>();
    let mut duplicated = records.clone();
    duplicated.push(records[0].clone());
    let indexed = index_relay_records(&frozen, duplicated).expect("identical duplicates collapse");
    assert_eq!(indexed.keys().copied().collect::<Vec<_>>(), vec![0, 1, 2]);

    let mut tampered = records[0].clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert!(index_relay_records(&frozen, vec![tampered]).is_err());
    assert!(
        index_relay_records(
            &casting_context(&open_lifecycle(&tle), &tle),
            records.clone()
        )
        .is_err(),
        "records cannot be relayed before the survivor freeze"
    );

    assert_eq!(relay_chunk(0, &indexed).expect("full").len(), 3);
    assert_eq!(relay_chunk(2, &indexed).expect("tail").len(), 1);
    let gap = BTreeMap::from([(0, records[0].clone()), (2, records[2].clone())]);
    assert_eq!(relay_chunk(0, &gap).expect("prefix before gap").len(), 1);
    assert!(relay_chunk(1, &gap).is_err(), "a gap cannot be relayed");
    assert!(relay_chunk(3, &indexed).is_err());

    let many = (0_u32..40)
        .map(|index| (index, vec![u8::try_from(index).expect("small index")]))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        relay_chunk(0, &many).expect("bounded chunk").len(),
        PARLIAMENT_TIMED_OVN_BALLOT_CHUNK_MAX_RECORDS_V1
    );
    assert_eq!(relay_chunk(32, &many).expect("next chunk").len(), 8);
}

// ---------------------------------------------------------------------------
// Scheduling and progress
// ---------------------------------------------------------------------------

#[test]
fn cast_schedule_follows_the_accepted_prefix() {
    assert_eq!(
        cast_schedule(0, 3, 0).expect("first"),
        CastSchedule::SubmitNow
    );
    assert_eq!(
        cast_schedule(0, 3, 2).expect("wait"),
        CastSchedule::Wait { missing: 2 }
    );
    assert_eq!(
        cast_schedule(2, 3, 2).expect("turn"),
        CastSchedule::SubmitNow
    );
    assert_eq!(
        cast_schedule(3, 3, 1).expect("done"),
        CastSchedule::AlreadyAccepted
    );
    assert_eq!(
        cast_schedule(2, 3, 1).expect("accepted"),
        CastSchedule::AlreadyAccepted
    );
    assert!(cast_schedule(0, 3, 3).is_err(), "seat outside the roster");
    assert!(cast_schedule(4, 3, 0).is_err(), "prefix beyond the roster");
}

fn body_state(
    body: ParliamentBody,
    progress: Option<ParliamentTimedOvnProgressProjectionV1>,
) -> ParliamentBodyStateProjectionV1 {
    ParliamentBodyStateProjectionV1 {
        body,
        body_instance_id: Some(BodyInstanceId::new(binding(12))),
        status: Some(BodyInstanceStatusV1::Balloting),
        public_finding_opened_at_height: None,
        public_finding_phase_blocks: None,
        public_finding_deadline_height: None,
        no_result_kind: None,
        no_result_height: None,
        timed_ovn_progress: progress,
    }
}

#[test]
fn ballot_progress_is_found_by_ballot_id() {
    let ballot = fixture_ballot_id();
    let other = BallotAttemptId::new(binding(0x0e));
    let states = [
        body_state(ParliamentBody::RulesCommittee, None),
        body_state(
            ParliamentBody::PolicyJury,
            Some(ParliamentTimedOvnProgressProjectionV1 {
                ballot_attempt_id: ballot,
                status: BallotAttemptStatusV1::TimedCommitment,
                frozen_survivor_count: Some(3),
                accepted_ballot_prefix_count: Some(1),
            }),
        ),
        body_state(
            ParliamentBody::ConfirmationJury,
            Some(ParliamentTimedOvnProgressProjectionV1 {
                ballot_attempt_id: other,
                status: BallotAttemptStatusV1::Registration,
                frozen_survivor_count: None,
                accepted_ballot_prefix_count: None,
            }),
        ),
    ];
    assert_eq!(
        find_ballot_progress(&states, ballot).expect("policy jury ballot"),
        BallotProgress {
            body: ParliamentBody::PolicyJury,
            status: BallotAttemptStatusV1::TimedCommitment,
            frozen_survivor_count: Some(3),
            accepted_prefix: Some(1),
        }
    );
    assert_eq!(
        find_ballot_progress(&states, other)
            .expect("confirmation ballot")
            .body,
        ParliamentBody::ConfirmationJury
    );
    assert!(find_ballot_progress(&states, BallotAttemptId::new(binding(0x0f))).is_err());
}

#[test]
fn status_participation_reports_registration_and_seat() {
    // Four jurors, so that three survivors remain after one dropout.
    let RegisteredJurors {
        tle,
        lifecycle,
        jurors,
        ..
    } = register_juror_count(4);
    let entry = |prefix: Option<u32>| {
        BallotStatusEntryV1::new(
            ParliamentBody::PolicyJury,
            &ParliamentTimedOvnProgressProjectionV1 {
                ballot_attempt_id: fixture_ballot_id(),
                status: BallotAttemptStatusV1::TimedCommitment,
                frozen_survivor_count: prefix.map(|_| 3),
                accepted_ballot_prefix_count: prefix,
            },
            &[0x33; 32],
        )
    };
    let registered = casting_context(&lifecycle, &tle);
    let hash = parliament_ballot_participant_hash_v1(fixture_ballot_id(), &jurors[0].0);
    let mut before = entry(None);
    apply_participation(&mut before, &registered, &hash, None).expect("registered participation");
    assert_eq!(before.registered, Some(true));
    assert_eq!(before.casting_phase.as_deref(), Some("Registered"));
    assert_eq!(before.casting_context_height, Some(25));
    assert_eq!(before.survivor_index, None);
    assert_eq!(
        before.dropped_out, None,
        "dropouts are known only after the freeze"
    );
    assert_eq!(
        before.key_file_matches_registration, None,
        "no key file supplied"
    );
    let mut with_key = entry(None);
    apply_participation(&mut with_key, &registered, &hash, Some(&jurors[0].1))
        .expect("participation with the registering key");
    assert_eq!(with_key.key_file_matches_registration, Some(true));
    let mut wrong_key = entry(None);
    apply_participation(&mut wrong_key, &registered, &hash, Some(&seed(0x99)))
        .expect("participation with another key");
    assert_eq!(
        wrong_key.key_file_matches_registration,
        Some(false),
        "a key file that did not register cannot cast"
    );
    let stranger = parliament_ballot_participant_hash_v1(fixture_ballot_id(), &account(0x5A));
    let mut outsider = entry(None);
    apply_participation(&mut outsider, &registered, &stranger, Some(&seed(0x6A)))
        .expect("outsider participation");
    assert_eq!(outsider.registered, Some(false));
    assert_eq!(outsider.key_file_matches_registration, None);

    let dropped_hash = parliament_ballot_participant_hash_v1(fixture_ballot_id(), &jurors[1].0);
    let frozen = lifecycle
        .close_registration(&tle)
        .and_then(|closed| closed.record_dropout(dropped_hash, &tle))
        .and_then(|closed| closed.freeze_survivors(&tle))
        .expect("freeze survivors");
    let frozen_context = casting_context(&frozen, &tle);
    let seat = survivor_seat(&frozen_context, &jurors[0].0).expect("seat");
    let mut after = entry(Some(seat.index + 1));
    apply_participation(&mut after, &frozen_context, &hash, Some(&jurors[0].1))
        .expect("frozen participation");
    assert_eq!(after.survivor_index, Some(seat.index));
    assert_eq!(after.ballot_accepted, Some(true));
    assert_eq!(after.dropped_out, Some(false));
    assert_eq!(after.key_file_matches_registration, Some(true));
    let mut pending = entry(Some(seat.index));
    apply_participation(&mut pending, &frozen_context, &hash, None).expect("pending participation");
    assert_eq!(pending.ballot_accepted, Some(false));
    let mut dropped = entry(Some(0));
    apply_participation(&mut dropped, &frozen_context, &dropped_hash, None)
        .expect("dropped participation");
    assert_eq!(dropped.registered, Some(true));
    assert_eq!(dropped.dropped_out, Some(true));
    assert_eq!(dropped.survivor_index, None);
    assert_eq!(dropped.ballot_accepted, None);
    let mut stranger_after = entry(Some(0));
    apply_participation(&mut stranger_after, &frozen_context, &stranger, None)
        .expect("stranger participation");
    assert_eq!(stranger_after.dropped_out, Some(false), "never registered");
    let rendered = norito::json::to_value(&after).expect("render status entry");
    assert!(rendered.get("survivor_index").is_some());
    assert!(rendered.get("key_file_matches_registration").is_some());
    let summary = after.summary();
    assert!(summary.contains("registered=true"), "{summary}");
    assert!(summary.contains("key_matches=true"), "{summary}");
    assert!(summary.contains("choice_lock=-"), "{summary}");
}

#[test]
fn status_entries_filter_ballots_and_record_context_failures() {
    let RegisteredJurors {
        tle,
        lifecycle,
        jurors,
        ..
    } = register_jurors();
    let ballot = fixture_ballot_id();
    let other = BallotAttemptId::new(binding(0x0e));
    let states = [
        body_state(ParliamentBody::RulesCommittee, None),
        body_state(
            ParliamentBody::PolicyJury,
            Some(ParliamentTimedOvnProgressProjectionV1 {
                ballot_attempt_id: ballot,
                status: BallotAttemptStatusV1::Registration,
                frozen_survivor_count: None,
                accepted_ballot_prefix_count: None,
            }),
        ),
        body_state(
            ParliamentBody::ConfirmationJury,
            Some(ParliamentTimedOvnProgressProjectionV1 {
                ballot_attempt_id: other,
                status: BallotAttemptStatusV1::AwaitingRelease,
                frozen_survivor_count: Some(3),
                accepted_ballot_prefix_count: Some(3),
            }),
        ),
    ];
    let custody = LocalCustody {
        key_file: None,
        seed: Some(seed(0x61)),
        key_file_present: Some(true),
        state: None,
        state_file_present: Some(false),
    };
    let mut requested = Vec::new();
    let entries = status_entries(&states, None, &jurors[0].0, &custody, |id| {
        requested.push(id);
        if id == ballot {
            Ok(casting_context(&lifecycle, &tle))
        } else {
            Err(eyre!("unexpected casting-context request"))
        }
    })
    .expect("status entries");
    assert_eq!(requested, vec![ballot], "sealed ballots are not castable");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].body, "PolicyJury");
    assert_eq!(entries[0].registered, Some(true));
    assert_eq!(
        entries[0].key_file_matches_registration,
        Some(true),
        "seed 0x61 registered juror 0x51"
    );
    assert_eq!(entries[1].status, "AwaitingRelease");
    assert_eq!(entries[1].registered, None);
    assert_eq!(entries[1].casting_phase, None);

    let only_other = status_entries(
        &states,
        Some(other),
        &jurors[0].0,
        &LocalCustody::default(),
        |_| Err(eyre!("no casting context for a sealed ballot")),
    )
    .expect("filtered entries");
    assert_eq!(only_other.len(), 1);
    assert_eq!(only_other[0].ballot_attempt_id, other.to_hex());

    let failing = status_entries(
        &states,
        Some(ballot),
        &jurors[0].0,
        &LocalCustody::default(),
        |_| Err(eyre!("casting context unavailable")),
    )
    .expect("a context failure is reported, not fatal");
    assert!(
        failing[0]
            .casting_context_error
            .as_deref()
            .is_some_and(|error| error.contains("unavailable"))
    );
    assert!(
        status_entries(
            &states,
            Some(BallotAttemptId::new(binding(0x0f))),
            &jurors[0].0,
            &LocalCustody::default(),
            |_| Err(eyre!("an unmatched ballot needs no casting context")),
        )
        .is_err(),
        "an unknown ballot is an error"
    );
}

#[cfg(unix)]
#[test]
fn local_custody_reads_present_files_and_reports_absent_ones() {
    let directory = tempfile::tempdir().expect("custody directory");
    let key = directory.path().join("juror.key");
    let network = fixture_network_id();

    let empty = LocalCustody::read(None, None, &network).expect("no files named");
    assert_eq!(empty.key_file_present, None);
    assert_eq!(empty.state_file_present, None);

    let absent = LocalCustody::read(Some(&key), None, &network).expect("absent files");
    assert_eq!(absent.key_file_present, Some(false));
    assert_eq!(absent.state_file_present, Some(false));
    assert!(absent.seed.is_none());
    assert!(!key.exists(), "status never creates a key file");
    assert!(!files::default_state_path(&key).exists());

    let (created, _) = files::load_or_create_key_file(&key).expect("create key");
    BallotState::open(
        &files::default_state_path(&key),
        *network.as_bytes(),
        Some(checkpoint(4, 9)),
    )
    .expect("initialize state");
    let ballot = fixture_ballot_id();
    let participant_hash = binding(0x77);
    files::lock_choice(
        &key,
        ballot.as_bytes(),
        &participant_hash,
        BallotChoiceArg::Abstain,
    )
    .expect("lock choice");
    let present = LocalCustody::read(Some(&key), None, &network).expect("present files");
    assert_eq!(present.key_file_present, Some(true));
    assert_eq!(present.state_file_present, Some(true));
    assert_eq!(
        present.seed.as_ref().map(TimedOvnSeedV1::as_bytes),
        Some(created.as_bytes())
    );
    assert_eq!(
        present.state.as_ref().map(BallotState::checkpoint),
        Some(checkpoint(4, 9))
    );
    assert_eq!(
        present
            .choice_lock(ballot, &participant_hash)
            .expect("read lock")
            .as_deref(),
        Some("abstain")
    );
    assert_eq!(
        present
            .choice_lock(ballot, &binding(0x79))
            .expect("other seat"),
        None,
        "locks are per seat"
    );
    assert!(
        present
            .choice_lock(BallotAttemptId::new(binding(0x0e)), &participant_hash)
            .is_err(),
        "a lock file naming another ballot is refused"
    );
    assert_eq!(
        LocalCustody::default()
            .choice_lock(ballot, &participant_hash)
            .expect("no key file"),
        None
    );

    let explicit_state = directory.path().join("elsewhere.json");
    let explicit = LocalCustody::read(Some(&key), Some(&explicit_state), &network)
        .expect("explicit absent state");
    assert_eq!(explicit.state_file_present, Some(false));

    let other_network = NetworkId::from_genesis_hash(
        HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed(binding(3))),
    );
    assert!(
        LocalCustody::read(Some(&key), None, &other_network).is_err(),
        "a state file of another network is refused"
    );
    set_mode(&key, 0o644);
    assert!(
        LocalCustody::read(Some(&key), None, &network).is_err(),
        "a loose key file is refused, not reported absent"
    );
}

#[cfg(unix)]
#[test]
fn state_args_resolve_open_and_initialize_state_files() {
    let directory = tempfile::tempdir().expect("state directory");
    let key = directory.path().join("juror.key");
    let network = fixture_network_id();
    let none = BallotStateArgs {
        state_file: None,
        trusted_checkpoint_file: None,
    };
    assert_eq!(none.path(None), None);
    assert_eq!(none.path(Some(&key)), Some(files::default_state_path(&key)));
    assert!(
        none.open(None, &network).expect("no state named").is_none(),
        "without files a command uses the public context"
    );
    let missing = none
        .open(Some(&key), &network)
        .expect_err("a named state file must exist");
    assert!(format!("{missing:#}").contains("--trusted-checkpoint-file"));

    let anchor = checkpoint(6, 2);
    let init_without_file = BallotStateArgs {
        state_file: None,
        trusted_checkpoint_file: Some(checkpoint_file(&anchor)),
    };
    assert!(init_without_file.open(None, &network).is_err());
    let explicit = directory.path().join("explicit.json");
    let init = BallotStateArgs {
        state_file: Some(explicit.clone()),
        ..init_without_file
    };
    assert_eq!(init.path(Some(&key)), Some(explicit.clone()));
    let opened = init
        .open(Some(&key), &network)
        .expect("initialize explicit state")
        .expect("state opened");
    assert_eq!(opened.checkpoint(), anchor);
    assert!(explicit.exists());
    assert!(
        !files::default_state_path(&key).exists(),
        "--state-file overrides the default path"
    );
    let missing_input = BallotStateArgs {
        state_file: Some(explicit.clone()),
        trusted_checkpoint_file: Some(directory.path().join("absent-checkpoint.nrt")),
    };
    assert!(missing_input.open(None, &network).is_err());

    let files_args = BallotFilesArgs {
        key_file: key.clone(),
        state: BallotStateArgs {
            state_file: None,
            trusted_checkpoint_file: Some(checkpoint_file(&anchor)),
        },
    };
    assert_eq!(
        files_args
            .open_state(&network)
            .expect("default state initialized")
            .checkpoint(),
        anchor
    );
    assert!(files::default_state_path(&key).exists());
}

#[cfg(unix)]
#[test]
fn read_only_loaders_report_absence_and_enforce_custody() {
    let directory = tempfile::tempdir().expect("loader directory");
    let key = directory.path().join("juror.key");
    assert!(
        files::load_key_file_if_present(&key)
            .expect("absent key")
            .is_none()
    );
    let (created, _) = files::load_or_create_key_file(&key).expect("create key");
    assert_eq!(
        files::load_key_file_if_present(&key)
            .expect("present key")
            .map(|seed| *seed.as_bytes()),
        Some(*created.as_bytes())
    );
    let link = directory.path().join("link.key");
    std::os::unix::fs::symlink(&key, &link).expect("symlink");
    assert!(files::load_key_file_if_present(&link).is_err());

    let network = *fixture_network_id().as_bytes();
    let state_path = directory.path().join("state.json");
    assert!(
        BallotState::load_if_present(&state_path, network)
            .expect("absent state")
            .is_none()
    );
    BallotState::open(&state_path, network, Some(checkpoint(5, 1))).expect("create state");
    assert_eq!(
        BallotState::load_if_present(&state_path, network)
            .expect("present state")
            .map(|state| state.checkpoint()),
        Some(checkpoint(5, 1))
    );
    assert!(BallotState::load_if_present(&state_path, binding(0x22)).is_err());
    set_mode(&state_path, 0o640);
    assert!(BallotState::load_if_present(&state_path, network).is_err());
}

// ---------------------------------------------------------------------------
// Consensus-authenticated casting context
// ---------------------------------------------------------------------------

/// Exact application SMT path alongside the mandatory native lane-state write.
fn casting_witness(
    snapshot: &ParliamentTimedOvnCastingSnapshotCommitmentV1,
) -> (ParliamentTimedOvnCastingWitnessProofV1, ExecWitness) {
    let lane_state = SumeragiLaneStateCommitment::from_state(
        fixture_network_id(),
        snapshot.evaluated_height,
        &Default::default(),
    )
    .expect("native lane-state commitment");
    let witness = ExecWitness {
        writes: vec![
            ExecKv {
                key: PARLIAMENT_TIMED_OVN_CASTING_WITNESS_KEY_V1.to_vec(),
                value: norito::to_bytes(snapshot).expect("canonical casting snapshot"),
            },
            ExecKv {
                key: SUMERAGI_LANE_STATE_WITNESS_KEY.to_vec(),
                value: norito::encode_canonical(&lane_state).expect("canonical lane state"),
            },
        ],
        ..Default::default()
    };
    let mut nodes: BTreeMap<[u8; 32], Hash> = witness
        .writes
        .iter()
        .map(|entry| {
            let path = Hash::new(&entry.key);
            let value = Hash::new(&entry.value);
            (
                *path.as_ref(),
                Hash::new_from_chunks(&[&[0], path.as_ref(), value.as_ref()]),
            )
        })
        .collect();
    let mut target: [u8; 32] = Hash::new(PARLIAMENT_TIMED_OVN_CASTING_WITNESS_KEY_V1).into();
    let mut siblings = Vec::new();
    for bit in (0..256).rev() {
        let mask = 1 << (bit % 8);
        let mut sibling = target;
        sibling[bit / 8] ^= mask;
        siblings.push(
            nodes
                .get(&sibling)
                .copied()
                .unwrap_or_else(|| Hash::new([])),
        );
        let mut parents = BTreeMap::new();
        for (path, hash) in &nodes {
            let mut sibling = *path;
            sibling[bit / 8] ^= mask;
            let other = nodes
                .get(&sibling)
                .copied()
                .unwrap_or_else(|| Hash::new([]));
            let (left, right) = if path[bit / 8] & mask == 0 {
                (*hash, other)
            } else {
                (other, *hash)
            };
            let mut parent = *path;
            parent[bit / 8] &= !mask;
            parents.insert(
                parent,
                Hash::new_from_chunks(&[&[1], left.as_ref(), right.as_ref()]),
            );
        }
        nodes = parents;
        target[bit / 8] &= !mask;
    }
    let proof = ParliamentTimedOvnCastingWitnessProofV1 {
        key: witness.writes[0].key.clone(),
        value: witness.writes[0].value.clone(),
        siblings,
    };
    assert!(proof.verify(nodes[&[0; 32]]));
    (proof, witness)
}

#[derive(Clone)]
struct CertifiedTestDecision {
    proof: SumeragiFinalityProof,
    checkpoint: SumeragiFinalityCheckpoint,
    context_id: Hash,
}

fn fixture_decision(fixture: &NativeFinalityFixture) -> CertifiedTestDecision {
    CertifiedTestDecision {
        proof: fixture.latest().clone(),
        checkpoint: fixture.checkpoint(),
        context_id: fixture
            .verifier()
            .verify_retained_decision(fixture.latest())
            .expect("retained native decision")
            .context_id(),
    }
}

/// Genuine native certificates over explicit synthetic test results.
fn finality_chain(tip_height: u64, tip_witness: &ExecWitness) -> Vec<CertifiedTestDecision> {
    let mut fixture = native_fixture();
    let mut chain = vec![fixture_decision(&fixture)];
    for height in 2..=tip_height {
        let block = fixture.block_with_submitted_work(fixture.next_header());
        if height == tip_height {
            fixture.certify_with_witness(block, tip_witness);
        } else {
            fixture.certify(block);
        }
        chain.push(fixture_decision(&fixture));
    }
    chain
}

fn checkpoint_of(decision: &CertifiedTestDecision) -> SumeragiFinalityCheckpoint {
    decision.checkpoint.clone()
}

/// A terminal casting proof for `context` whose chain begins at height 1, plus
/// the complete chain for building intermediate pages.
fn terminal_page(
    context: &ValidatedParliamentTimedOvnCastingContextArchiveV1,
) -> (
    ParliamentTimedOvnCastingProofResponseV1,
    Vec<CertifiedTestDecision>,
) {
    let binding = context
        .compact_binding_v1(
            REGISTRATION_CLOSE_HEIGHT,
            SURVIVOR_FREEZE_HEIGHT,
            COMMITMENT_CLOSE_HEIGHT,
        )
        .expect("compact casting binding");
    let snapshot = ParliamentTimedOvnCastingSnapshotCommitmentV1::from_ordered_bindings(
        binding.evaluated_height,
        std::slice::from_ref(&binding),
    )
    .expect("casting snapshot");
    let tree = MerkleTree::from_iter([HashOf::new(&binding)]);
    let membership = ParliamentTimedOvnCastingContextMembershipProofV1::new(
        tree.get_proof(0).expect("single casting leaf proof"),
    );
    let (witness, execution_witness) = casting_witness(&snapshot);
    let chain = finality_chain(binding.evaluated_height, &execution_witness);
    let tip = chain.last().expect("evaluated proof");
    let response = ParliamentTimedOvnCastingProofResponseV1 {
        version: PARLIAMENT_TIMED_OVN_CASTING_PROOF_VERSION_V1,
        casting_context_archive: Some(
            context
                .archive()
                .to_canonical_bytes_v1()
                .expect("canonical casting archive"),
        ),
        casting_context_binding: Some(binding.clone()),
        context_membership_proof: Some(membership),
        casting_witness: Some(witness),
        finality_chain: chain
            .iter()
            .map(|decision| decision.proof.clone())
            .collect(),
        evaluated_context_id: tip.context_id,
        evaluated_block_height: binding.evaluated_height,
        evaluated_block_hash: hex::encode(tip.proof.block_header.hash().as_ref()),
        observed_ledger_tip_height: binding.evaluated_height,
        more_available: false,
    };
    (response, chain)
}

/// Split a terminal page into an intermediate page ending at `split` and the
/// terminal page that continues from there.
fn split_pages(
    terminal: &ParliamentTimedOvnCastingProofResponseV1,
    chain: &[CertifiedTestDecision],
    split: u64,
) -> (
    ParliamentTimedOvnCastingProofResponseV1,
    ParliamentTimedOvnCastingProofResponseV1,
) {
    let split_index = usize::try_from(split).expect("split height") - 1;
    let middle = &chain[split_index];
    let intermediate = ParliamentTimedOvnCastingProofResponseV1 {
        version: PARLIAMENT_TIMED_OVN_CASTING_PROOF_VERSION_V1,
        casting_context_archive: None,
        casting_context_binding: None,
        context_membership_proof: None,
        casting_witness: None,
        finality_chain: chain[..=split_index]
            .iter()
            .map(|decision| decision.proof.clone())
            .collect(),
        evaluated_context_id: middle.context_id,
        evaluated_block_height: split,
        evaluated_block_hash: hex::encode(middle.proof.block_header.hash().as_ref()),
        observed_ledger_tip_height: terminal.evaluated_block_height,
        more_available: true,
    };
    let mut rest = terminal.clone();
    rest.finality_chain = chain[split_index..]
        .iter()
        .map(|decision| decision.proof.clone())
        .collect();
    (intermediate, rest)
}

#[test]
fn casting_pages_authenticate_promote_and_reject_tampering() {
    let RegisteredJurors { tle, lifecycle, .. } = register_jurors();
    let frozen = lifecycle
        .close_registration(&tle)
        .and_then(|closed| closed.freeze_survivors(&tle))
        .expect("freeze survivors");
    let context = casting_context(&frozen, &tle);
    let (terminal, chain) = terminal_page(&context);
    let anchor = checkpoint_of(&chain[0]);
    let network = fixture_network_id();
    let ballot = fixture_ballot_id();

    match authenticate_casting_page(&terminal, network, &anchor, ballot).expect("terminal page") {
        CastingPageOutcome::Terminal {
            checkpoint,
            context: authenticated,
            binding,
        } => {
            assert_eq!(checkpoint, checkpoint_of(chain.last().expect("tip")));
            assert_eq!(authenticated.archive(), context.archive());
            assert_eq!(binding.commitment_close_height, COMMITMENT_CLOSE_HEIGHT);
        }
        CastingPageOutcome::Promote(_) => panic!("expected a terminal page"),
    }

    let (intermediate, rest) = split_pages(&terminal, &chain, 17);
    match authenticate_casting_page(&intermediate, network, &anchor, ballot)
        .expect("intermediate page")
    {
        CastingPageOutcome::Promote(next) => assert_eq!(next, checkpoint_of(&chain[16])),
        CastingPageOutcome::Terminal { .. } => panic!("expected a promotion page"),
    }
    assert!(
        authenticate_casting_page(&rest, network, &anchor, ballot).is_err(),
        "the continuation must begin at the promoted checkpoint"
    );
    assert!(matches!(
        authenticate_casting_page(&rest, network, &checkpoint_of(&chain[16]), ballot),
        Ok(CastingPageOutcome::Terminal { .. })
    ));

    let wrong_anchor = checkpoint(2, 17);
    assert!(authenticate_casting_page(&terminal, network, &wrong_anchor, ballot).is_err());
    assert!(
        authenticate_casting_page(
            &terminal,
            network,
            &anchor,
            BallotAttemptId::new(binding(0x0e))
        )
        .is_err()
    );
    let other_network = NetworkId::from_genesis_hash(
        HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed(binding(3))),
    );
    assert!(authenticate_casting_page(&terminal, other_network, &anchor, ballot).is_err());

    let mut forged = terminal.clone();
    forged.finality_chain.last_mut().expect("tip").block_wire[0] ^= 0x80;
    assert!(authenticate_casting_page(&forged, network, &anchor, ballot).is_err());

    // A different, individually valid archive does not rederive the binding.
    let registered_context = casting_context(&open_lifecycle(&tle), &tle);
    let mut substituted = terminal.clone();
    substituted.casting_context_archive = Some(
        registered_context
            .archive()
            .to_canonical_bytes_v1()
            .expect("alternate archive"),
    );
    assert!(authenticate_casting_page(&substituted, network, &anchor, ballot).is_err());

    let mut truncated = terminal.clone();
    truncated.casting_context_archive = Some(Vec::new());
    assert!(authenticate_casting_page(&truncated, network, &anchor, ballot).is_err());
}

/// One recorded stub-server request: its request line and body.
type StubRequest = (String, Vec<u8>);

/// Serve `bodies` in order as Norito responses and report each request.
fn spawn_norito_server(
    bodies: Vec<Vec<u8>>,
) -> (Url, mpsc::Receiver<StubRequest>, thread::JoinHandle<()>) {
    spawn_stub_server(
        bodies
            .into_iter()
            .map(|body| ("application/x-norito", body))
            .collect(),
    )
}

/// Serve `(content type, body)` responses in order and report each request.
fn spawn_stub_server(
    responses: Vec<(&'static str, Vec<u8>)>,
) -> (Url, mpsc::Receiver<StubRequest>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind Torii stub");
    let address = listener.local_addr().expect("server address");
    let (sender, receiver) = mpsc::channel();
    let handle = thread::spawn(move || {
        for (content_type, body) in responses {
            let (mut stream, _) = listener.accept().expect("accept request");
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .expect("set read timeout");
            let mut raw = Vec::new();
            let mut chunk = [0_u8; 8192];
            let header_end = loop {
                let read = stream.read(&mut chunk).expect("read request");
                assert!(read > 0, "request ended before its headers");
                raw.extend_from_slice(&chunk[..read]);
                if let Some(position) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
                    break position + 4;
                }
            };
            let head = String::from_utf8_lossy(&raw[..header_end]).to_ascii_lowercase();
            let content_length = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .map_or(0, |value| {
                    value.trim().parse::<usize>().expect("content length")
                });
            while raw.len() < header_end + content_length {
                let read = stream.read(&mut chunk).expect("read request body");
                assert!(read > 0, "request ended before its body");
                raw.extend_from_slice(&chunk[..read]);
            }
            let request_line = head.lines().next().unwrap_or_default().to_owned();
            sender
                .send((
                    request_line,
                    raw[header_end..header_end + content_length].to_vec(),
                ))
                .expect("record request");
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .expect("write response headers");
            stream.write_all(&body).expect("write response body");
        }
    });
    (
        Url::parse(&format!("http://{address}")).expect("server URL"),
        receiver,
        handle,
    )
}

#[cfg(unix)]
#[test]
fn authenticated_fetch_walks_pages_and_persists_the_checkpoint() {
    let RegisteredJurors {
        tle,
        lifecycle,
        jurors,
        ..
    } = register_jurors();
    let frozen = lifecycle
        .close_registration(&tle)
        .and_then(|closed| closed.freeze_survivors(&tle))
        .expect("freeze survivors");
    let context = casting_context(&frozen, &tle);
    let (terminal, chain) = terminal_page(&context);
    let (intermediate, rest) = split_pages(&terminal, &chain, 20);
    let (url, requests, server) = spawn_norito_server(vec![
        norito::to_bytes(&intermediate).expect("encode intermediate page"),
        norito::to_bytes(&rest).expect("encode terminal page"),
    ]);

    let mut config = crate::fallback_config();
    config.network_id = fixture_network_id();
    config.torii_api_url = url;
    let client = Client::builder(config).build().expect("client");
    let directory = tempfile::tempdir().expect("state directory");
    let state_path = directory.path().join("juror.key.state.nrt");
    let anchor = checkpoint_of(&chain[0]);
    let mut state = BallotState::open(
        &state_path,
        *fixture_network_id().as_bytes(),
        Some(anchor.clone()),
    )
    .expect("initialize state");

    let authenticated = fetch_authenticated_casting_context(
        &client,
        fixture_network_id(),
        fixture_ballot_id(),
        &mut state,
    )
    .expect("authenticated casting context");
    server.join().expect("join server");
    let bodies = requests.into_iter().collect::<Vec<_>>();
    let heights = bodies
        .iter()
        .map(|(_, body)| {
            norito::decode_from_bytes::<ParliamentTimedOvnCastingProofRequestV1>(body)
                .expect("casting proof request")
                .trusted_checkpoint_height
        })
        .collect::<Vec<_>>();
    assert_eq!(
        heights,
        vec![1, 20],
        "the second page starts at the promoted checkpoint"
    );
    assert_eq!(authenticated.context.archive(), context.archive());
    assert_eq!(
        authenticated.binding.survivor_freeze_height,
        SURVIVOR_FREEZE_HEIGHT
    );
    let tip = checkpoint_of(chain.last().expect("tip"));
    assert_eq!(state.checkpoint(), tip);
    assert_eq!(
        BallotState::open(&state_path, *fixture_network_id().as_bytes(), None)
            .expect("reload state")
            .checkpoint(),
        tip,
        "promotions are durable"
    );
    let seat = survivor_seat(&authenticated.context, &jurors[2].0).expect("seat");
    assert!(seat.index < 3);
}

#[test]
fn corpus_instruction_wraps_one_exact_chunk() {
    let record = vec![0x5C_u8; TIMED_OVN_BALLOT_RECORD_BYTES_V1];
    let instruction = corpus_instruction(
        GovernanceAttemptId::new(binding(11)),
        fixture_ballot_id(),
        vec![record.clone()],
    )
    .expect("statically valid chunk");
    let submitted = instruction
        .as_any()
        .downcast_ref::<iroha_data_model::isi::governance::SubmitParliamentLifecycleTransitionV1>()
        .expect("lifecycle transition");
    assert_eq!(
        submitted.governance_attempt_id,
        GovernanceAttemptId::new(binding(11))
    );
    let ParliamentLifecycleTransitionV1::FreezeTimedOvnCorpus(payload) = &submitted.transition
    else {
        panic!("expected a corpus chunk")
    };
    assert_eq!(payload.ballot_attempt_id, fixture_ballot_id());
    assert_eq!(payload.ballot_records, vec![record]);
    assert!(
        corpus_instruction(
            GovernanceAttemptId::new(binding(11)),
            fixture_ballot_id(),
            vec![vec![1, 2, 3]],
        )
        .is_err(),
        "records of the wrong width are refused before submission"
    );
    assert!(
        corpus_instruction(
            GovernanceAttemptId::new(binding(11)),
            fixture_ballot_id(),
            Vec::new(),
        )
        .is_err(),
        "an empty chunk is refused before submission"
    );
}

// ---------------------------------------------------------------------------
// Seat-bound choice locks and concurrent state promotion
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn choice_locks_are_seat_bound_and_never_change() {
    let directory = tempfile::tempdir().expect("lock directory");
    let key = directory.path().join("juror.key");
    files::load_or_create_key_file_with(&key, || Ok(seed(0x61))).expect("key file");
    let ballot = binding(0x0d);
    let seat = binding(0x71);
    let lock_path = files::choice_lock_path(&key, &seat);
    assert_eq!(
        lock_path,
        directory
            .path()
            .join(format!("juror.key.choice-{}", hex::encode(seat)))
    );
    assert_eq!(
        files::read_choice_lock(&key, &ballot, &seat).expect("no lock"),
        None
    );
    files::check_choice_lock(&key, &ballot, &seat, BallotChoiceArg::Approve)
        .expect("nothing locked yet");

    // Every call reads the file afresh, as separate processes would.
    files::lock_choice(&key, &ballot, &seat, BallotChoiceArg::Reject).expect("first lock");
    assert_eq!(mode_of(&lock_path), 0o600);
    files::lock_choice(&key, &ballot, &seat, BallotChoiceArg::Reject).expect("same choice");
    let refused = files::lock_choice(&key, &ballot, &seat, BallotChoiceArg::Approve)
        .expect_err("a different choice must be refused");
    assert!(format!("{refused:#}").contains("reveal both choices"));
    assert!(files::check_choice_lock(&key, &ballot, &seat, BallotChoiceArg::Abstain).is_err());
    files::check_choice_lock(&key, &ballot, &seat, BallotChoiceArg::Reject)
        .expect("the locked choice passes the early check");
    assert_eq!(
        files::read_choice_lock(&key, &ballot, &seat).expect("lock"),
        Some(BallotChoiceArg::Reject)
    );

    // Another seat (another account or ballot) has its own lock.
    files::lock_choice(&key, &ballot, &binding(0x72), BallotChoiceArg::Approve)
        .expect("independent seat");
    assert!(
        files::read_choice_lock(&key, &binding(0x0f), &seat).is_err(),
        "a lock naming another ballot is refused, not ignored"
    );

    // A lock copied to another seat's name is refused.
    let copied_seat = binding(0x73);
    std::fs::copy(&lock_path, files::choice_lock_path(&key, &copied_seat)).expect("copy lock");
    set_mode(&files::choice_lock_path(&key, &copied_seat), 0o600);
    let copied = files::read_choice_lock(&key, &ballot, &copied_seat).expect_err("copied lock");
    assert!(format!("{copied:#}").contains("another seat"));

    // Custody failures refuse rather than unlock.
    set_mode(&lock_path, 0o644);
    assert!(files::lock_choice(&key, &ballot, &seat, BallotChoiceArg::Reject).is_err());
    assert!(files::check_choice_lock(&key, &ballot, &seat, BallotChoiceArg::Approve).is_err());
    set_mode(&lock_path, 0o600);
    let linked_seat = binding(0x74);
    std::os::unix::fs::symlink(&lock_path, files::choice_lock_path(&key, &linked_seat))
        .expect("symlink lock");
    assert!(
        files::lock_choice(&key, &ballot, &linked_seat, BallotChoiceArg::Approve).is_err(),
        "a symlinked lock is neither followed nor replaced"
    );
    std::fs::write(files::choice_lock_path(&key, &binding(0x75)), b"approve")
        .expect("write garbage lock");
    set_mode(&files::choice_lock_path(&key, &binding(0x75)), 0o600);
    assert!(files::read_choice_lock(&key, &ballot, &binding(0x75)).is_err());
}

#[cfg(unix)]
#[test]
fn concurrent_choice_locks_admit_exactly_one_choice() {
    let directory = tempfile::tempdir().expect("lock directory");
    let key = directory.path().join("juror.key");
    let ballot = binding(0x0d);
    let seat = binding(0x71);
    let choices = [
        BallotChoiceArg::Approve,
        BallotChoiceArg::Reject,
        BallotChoiceArg::Abstain,
    ];
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(9));
    let handles = (0..9)
        .map(|index| {
            let key = key.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            let choice = choices[index % choices.len()];
            thread::spawn(move || {
                barrier.wait();
                (
                    choice.label(),
                    files::lock_choice(&key, &ballot, &seat, choice).is_ok(),
                )
            })
        })
        .collect::<Vec<_>>();
    let winners = handles
        .into_iter()
        .map(|handle| handle.join().expect("lock thread"))
        .filter_map(|(label, locked)| locked.then_some(label))
        .collect::<std::collections::BTreeSet<_>>();
    let locked = files::read_choice_lock(&key, &ballot, &seat)
        .expect("read lock")
        .expect("one lock exists");
    assert_eq!(
        winners,
        std::collections::BTreeSet::from([locked.label()]),
        "every successful caller holds the one locked choice"
    );
}

#[cfg(unix)]
#[test]
fn state_promotion_never_regresses_a_concurrently_promoted_file() {
    let directory = tempfile::tempdir().expect("state directory");
    let path = directory.path().join("state.json");
    let network = *fixture_network_id().as_bytes();
    BallotState::open(&path, network, Some(checkpoint(3, 5))).expect("initialize");
    let mut first = BallotState::open(&path, network, None).expect("first command");
    let mut second = BallotState::open(&path, network, None).expect("second command");

    first.promote(checkpoint(9, 5)).expect("first promotes");
    second
        .promote(checkpoint(6, 5))
        .expect("a stale command promotes its own walk");
    assert_eq!(second.checkpoint(), checkpoint(6, 5));
    assert_eq!(
        BallotState::load(&path).expect("reload").checkpoint(),
        checkpoint(9, 5),
        "the stale command does not regress the file"
    );
    let fork = second
        .promote(checkpoint(9, 8))
        .expect_err("a different checkpoint at the stored height");
    assert!(format!("{fork:#}").contains("disagree"));
    second.promote(checkpoint(12, 5)).expect("advance past it");
    assert_eq!(
        BallotState::load(&path).expect("reload").checkpoint(),
        checkpoint(12, 5)
    );
    first
        .promote(checkpoint(12, 5))
        .expect("the same checkpoint written by another command");
}

// ---------------------------------------------------------------------------
// Public archives
// ---------------------------------------------------------------------------

#[test]
fn public_archives_must_be_canonical_bounded_and_name_the_ballot() {
    use base64::Engine as _;
    let RegisteredJurors { tle, lifecycle, .. } = register_jurors();
    let context = casting_context(&lifecycle, &tle);
    let bytes = context
        .archive()
        .to_canonical_bytes_v1()
        .expect("canonical archive");
    let encoded = BASE64_STANDARD.encode(&bytes);
    assert_eq!(
        public_casting_archive(&encoded, fixture_ballot_id())
            .expect("canonical archive")
            .archive(),
        context.archive()
    );
    let other_ballot = public_casting_archive(&encoded, BallotAttemptId::new(binding(0x0e)))
        .expect_err("archive of another ballot");
    assert!(format!("{other_ballot:#}").contains("different ballot"));

    let base64_error = |input: &str| {
        format!(
            "{:#}",
            public_casting_archive(input, fixture_ballot_id()).expect_err("rejected")
        )
    };
    for malformed in ["YWJjZA", "YWJjZB==", "-_8=", "YWJj\nZA==", " YWJjZA=="] {
        assert!(
            base64_error(malformed).contains("canonical padded standard base64"),
            "{malformed:?}"
        );
    }
    assert!(
        !base64_error("YWJjZA==").contains("base64"),
        "canonical base64 reaches the archive decoder"
    );
    assert!(base64_error("").contains("base64 bound"));
    assert!(
        base64_error(
            &"A".repeat(PARLIAMENT_TIMED_OVN_CASTING_CONTEXT_ARCHIVE_MAX_BASE64_BYTES_V1 + 4)
        )
        .contains("base64 bound")
    );
    let mut tampered = bytes;
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert!(
        public_casting_archive(&BASE64_STANDARD.encode(&tampered), fixture_ballot_id()).is_err()
    );
}

// ---------------------------------------------------------------------------
// Cast driver
// ---------------------------------------------------------------------------

fn progress_at(status: BallotAttemptStatusV1, accepted_prefix: Option<u32>) -> BallotProgress {
    BallotProgress {
        body: ParliamentBody::PolicyJury,
        status,
        frozen_survivor_count: Some(3),
        accepted_prefix,
    }
}

/// Run [`drive_cast`] for seat 2 of 3 over scripted progress reads, counting
/// builds and waits.
fn drive_scripted(
    reads: Vec<Result<BallotProgress>>,
    build_result: fn() -> Result<Vec<u8>>,
    waits_allowed: usize,
) -> (Result<CastOutcome>, usize, usize) {
    let seat = SurvivorSeat {
        participant_hash: binding(0x71),
        index: 2,
        survivor_count: 3,
    };
    let mut reads = std::collections::VecDeque::from(reads);
    let builds = std::cell::Cell::new(0_usize);
    let waits = std::cell::Cell::new(0_usize);
    let outcome = drive_cast(
        seat,
        || reads.pop_front().expect("scripted progress read"),
        || {
            builds.set(builds.get() + 1);
            build_result()
        },
        || {
            waits.set(waits.get() + 1);
            waits.get() <= waits_allowed
        },
    );
    (outcome, builds.get(), waits.get())
}

fn built_record() -> Result<Vec<u8>> {
    Ok(vec![0xB1; 4])
}

#[test]
fn cast_driver_builds_once_and_follows_the_accepted_prefix() {
    use BallotAttemptStatusV1::{AwaitingRelease, TimedCommitment};

    let (outcome, builds, waits) = drive_scripted(
        vec![Ok(progress_at(TimedCommitment, Some(2)))],
        built_record,
        0,
    );
    assert_eq!(outcome.expect("submit"), CastOutcome::Submit(vec![0xB1; 4]));
    assert_eq!((builds, waits), (1, 0));

    let (outcome, builds, waits) = drive_scripted(
        vec![
            Ok(progress_at(TimedCommitment, Some(0))),
            Ok(progress_at(TimedCommitment, Some(1))),
            Ok(progress_at(TimedCommitment, Some(2))),
        ],
        built_record,
        5,
    );
    assert_eq!(
        outcome.expect("submit after waiting"),
        CastOutcome::Submit(vec![0xB1; 4])
    );
    assert_eq!(
        (builds, waits),
        (1, 2),
        "the record is built and exported once, before the seat's turn"
    );

    let (outcome, builds, _) = drive_scripted(
        vec![Ok(progress_at(TimedCommitment, Some(3)))],
        built_record,
        0,
    );
    assert_eq!(
        outcome.expect("already accepted"),
        CastOutcome::AlreadyAccepted { accepted_prefix: 3 }
    );
    assert_eq!(builds, 0, "an accepted seat never builds a ballot");

    let (outcome, builds, waits) = drive_scripted(
        vec![
            Ok(progress_at(TimedCommitment, Some(1))),
            Ok(progress_at(TimedCommitment, Some(1))),
        ],
        built_record,
        1,
    );
    let expired = format!("{:#}", outcome.expect_err("deadline"));
    assert!(expired.contains("1 earlier survivor(s)"), "{expired}");
    assert_eq!((builds, waits), (1, 2));

    let (outcome, builds, _) = drive_scripted(
        vec![
            Ok(progress_at(TimedCommitment, Some(0))),
            Ok(progress_at(AwaitingRelease, Some(3))),
        ],
        built_record,
        5,
    );
    assert!(format!("{:#}", outcome.expect_err("sealed")).contains("no longer accepts"));
    assert_eq!(builds, 1);

    let (outcome, _, waits) = drive_scripted(
        vec![Ok(progress_at(TimedCommitment, Some(2)))],
        || Err(eyre!("would reveal both choices")),
        5,
    );
    assert!(format!("{:#}", outcome.expect_err("lock refusal")).contains("reveal both choices"));
    assert_eq!(waits, 0);

    let (outcome, builds, _) =
        drive_scripted(vec![Err(eyre!("attempt unreadable"))], built_record, 5);
    assert!(format!("{:#}", outcome.expect_err("read error")).contains("unreadable"));
    assert_eq!(builds, 0);

    let mut resized = progress_at(TimedCommitment, Some(2));
    resized.frozen_survivor_count = Some(4);
    let (outcome, builds, _) = drive_scripted(vec![Ok(resized)], built_record, 5);
    assert!(format!("{:#}", outcome.expect_err("roster mismatch")).contains("inconsistent"));
    assert_eq!(builds, 0);

    let (outcome, builds, _) = drive_scripted(
        vec![Ok(progress_at(TimedCommitment, None))],
        built_record,
        5,
    );
    assert!(outcome.is_err(), "a missing prefix is refused");
    assert_eq!(builds, 0);
}

#[test]
fn poll_waits_end_at_the_deadline() {
    assert!(
        !wait_for_next_poll(Instant::now()),
        "a spent budget ends the wait"
    );
    let start = Instant::now();
    assert!(wait_for_next_poll(start + Duration::from_millis(20)));
    let elapsed = start.elapsed();
    assert!(elapsed >= Duration::from_millis(20), "{elapsed:?}");
    assert!(
        elapsed < CAST_POLL_INTERVAL,
        "the sleep stops at the deadline"
    );
}

// ---------------------------------------------------------------------------
// Command execution against a scripted Torii
// ---------------------------------------------------------------------------

use super::super::test_context::CaptureContext;

/// Scripted [`BallotSource`] that records every read.
#[derive(Default)]
struct ScriptedSource {
    proof_pages:
        std::cell::RefCell<std::collections::VecDeque<ParliamentTimedOvnCastingProofResponseV1>>,
    proof_requests: std::cell::RefCell<Vec<SumeragiFinalityCheckpoint>>,
    public_archives: Vec<(BallotAttemptId, Vec<u8>)>,
    public_requests: std::cell::RefCell<Vec<BallotAttemptId>>,
    attempts: std::cell::RefCell<std::collections::VecDeque<AttemptSnapshot>>,
    attempt_requests: std::cell::RefCell<Vec<GovernanceAttemptId>>,
}

impl ScriptedSource {
    fn with_pages(pages: Vec<ParliamentTimedOvnCastingProofResponseV1>) -> Self {
        Self {
            proof_pages: std::cell::RefCell::new(pages.into()),
            ..Self::default()
        }
    }

    fn with_public(mut self, context: &ValidatedParliamentTimedOvnCastingContextArchiveV1) -> Self {
        self.public_archives.push((
            archive_ballot_attempt_id(context),
            context
                .archive()
                .to_canonical_bytes_v1()
                .expect("canonical archive"),
        ));
        self
    }

    fn with_attempt(self, snapshot: AttemptSnapshot) -> Self {
        self.attempts.borrow_mut().push_back(snapshot);
        self
    }
}

impl BallotSource for ScriptedSource {
    fn casting_proof_page(
        &self,
        ballot_attempt_id: BallotAttemptId,
        checkpoint: &SumeragiFinalityCheckpoint,
    ) -> Result<ParliamentTimedOvnCastingProofResponseV1> {
        assert_eq!(ballot_attempt_id, fixture_ballot_id());
        self.proof_requests.borrow_mut().push(checkpoint.clone());
        self.proof_pages
            .borrow_mut()
            .pop_front()
            .ok_or_else(|| eyre!("no scripted casting-proof page"))
    }

    fn public_casting_context(
        &self,
        ballot_attempt_id: BallotAttemptId,
    ) -> Result<ValidatedParliamentTimedOvnCastingContextArchiveV1> {
        use base64::Engine as _;
        self.public_requests.borrow_mut().push(ballot_attempt_id);
        let (_, bytes) = self
            .public_archives
            .iter()
            .find(|(ballot, _)| *ballot == ballot_attempt_id)
            .ok_or_else(|| eyre!("no scripted public casting context"))?;
        public_casting_archive(&BASE64_STANDARD.encode(bytes), ballot_attempt_id)
    }

    fn attempt(&self, governance_attempt_id: GovernanceAttemptId) -> Result<AttemptSnapshot> {
        self.attempt_requests
            .borrow_mut()
            .push(governance_attempt_id);
        self.attempts
            .borrow_mut()
            .pop_front()
            .ok_or_else(|| eyre!("no scripted attempt"))
    }
}

fn juror_key(byte: u8) -> KeyPair {
    KeyPair::try_from_seed(vec![byte; 32], Algorithm::Ed25519).expect("juror key")
}

/// Capture context of juror `byte` (the account of [`account`]).
fn capture(byte: u8) -> CaptureContext {
    let context = CaptureContext::new(juror_key(byte), fixture_network_id());
    assert_eq!(context.config().account, account(byte));
    context
}

fn checkpoint_file(checkpoint: &SumeragiFinalityCheckpoint) -> PathBuf {
    // Each test thread owns and cleans its independently selected input files.
    thread_local! {
        static CHECKPOINT_FILES: tempfile::TempDir = tempfile::tempdir().expect("checkpoint inputs");
    }
    CHECKPOINT_FILES.with(|directory| {
        let bytes = checkpoint.encode_canonical().expect("canonical checkpoint");
        let path = directory
            .path()
            .join(format!("{}.nrt", hex::encode(Hash::new(&bytes).as_ref())));
        std::fs::write(&path, bytes).expect("write trusted checkpoint");
        #[cfg(unix)]
        set_mode(&path, 0o600);
        path
    })
}

fn state_args(
    state_file: Option<PathBuf>,
    init: Option<SumeragiFinalityCheckpoint>,
) -> BallotStateArgs {
    BallotStateArgs {
        state_file,
        trusted_checkpoint_file: init.as_ref().map(checkpoint_file),
    }
}

fn attempt_with(
    status: BallotAttemptStatusV1,
    frozen_survivor_count: Option<u32>,
    accepted_prefix: Option<u32>,
) -> AttemptSnapshot {
    AttemptSnapshot {
        current_height: 37,
        body_states: vec![
            body_state(ParliamentBody::RulesCommittee, None),
            body_state(
                ParliamentBody::PolicyJury,
                Some(ParliamentTimedOvnProgressProjectionV1 {
                    ballot_attempt_id: fixture_ballot_id(),
                    status,
                    frozen_survivor_count,
                    accepted_ballot_prefix_count: accepted_prefix,
                }),
            ),
        ],
    }
}

/// A terminal page for the same context whose chain begins at `chain[start]`.
fn page_from(
    terminal: &ParliamentTimedOvnCastingProofResponseV1,
    chain: &[CertifiedTestDecision],
    start: usize,
) -> ParliamentTimedOvnCastingProofResponseV1 {
    let mut page = terminal.clone();
    page.finality_chain = chain[start..]
        .iter()
        .map(|decision| decision.proof.clone())
        .collect();
    page
}

fn frozen_jurors() -> (
    RegisteredJurors,
    TimedOvnLifecycleStateV1,
    ValidatedParliamentTimedOvnCastingContextArchiveV1,
) {
    let jurors = register_jurors();
    let frozen = jurors
        .lifecycle
        .clone()
        .close_registration(&jurors.tle)
        .and_then(|closed| closed.freeze_survivors(&jurors.tle))
        .expect("freeze survivors");
    let context = casting_context(&frozen, &jurors.tle);
    (jurors, frozen, context)
}

#[cfg(unix)]
#[test]
fn register_opens_the_trust_anchor_first_and_submits_the_seeded_record() {
    let RegisteredJurors { tle, lifecycle, .. } = register_jurors();
    let registered = casting_context(&lifecycle, &tle);
    let (terminal, chain) = terminal_page(&registered);
    let anchor = checkpoint_of(&chain[0]);
    let tip = checkpoint_of(chain.last().expect("tip"));
    let directory = tempfile::tempdir().expect("juror directory");
    let key = directory.path().join("juror.key");
    let newcomer = 0x54;
    let register = |state: BallotStateArgs, key_file: &Path| RegisterArgs {
        ballot_attempt_id: fixture_ballot_id(),
        files: BallotFilesArgs {
            key_file: key_file.to_path_buf(),
            state,
        },
    };

    let source = ScriptedSource::with_pages(vec![terminal.clone()]);
    let missing = register(state_args(None, None), &key)
        .execute(&mut capture(newcomer), &source)
        .expect_err("a trust anchor is required");
    assert!(format!("{missing:#}").contains("--trusted-checkpoint-file"));
    assert!(
        !key.exists(),
        "no key file is generated without a trust anchor"
    );
    assert!(source.proof_requests.borrow().is_empty());

    let mut context = capture(newcomer).text();
    register(state_args(None, Some(anchor.clone())), &key)
        .execute(&mut context, &source)
        .expect("register");
    assert_eq!(mode_of(&key), 0o600);
    assert_eq!(*source.proof_requests.borrow(), vec![anchor]);
    assert_eq!(
        BallotState::load(&files::default_state_path(&key))
            .expect("state")
            .checkpoint(),
        tip,
        "the checkpoint is promoted durably"
    );
    assert!(context.lines[0].contains("generated a new timed-OVN key file"));
    assert!(context.lines[1].contains("registering participant_hash="));
    let key_seed = files::load_key_file(&key).expect("generated key");
    let participant_hash =
        parliament_ballot_participant_hash_v1(fixture_ballot_id(), &account(newcomer));
    let transition = context.single_transition();
    assert_eq!(
        transition.governance_attempt_id,
        GovernanceAttemptId::new(binding(11))
    );
    let ParliamentLifecycleTransitionV1::RegisterBallotParticipant(payload) =
        &transition.transition
    else {
        panic!("expected a registration")
    };
    assert_eq!(payload.ballot_attempt_id, fixture_ballot_id());
    assert_eq!(
        payload.registration_record,
        seeded_registration_record(&registered, participant_hash, &key_seed)
            .expect("seeded record")
    );
    let accepted = lifecycle
        .register_participant(participant_hash, payload.registration_record.clone(), &tle)
        .expect("Core accepts the submitted registration");

    // Rerunning after the registration committed submits nothing.
    let committed = casting_context(&accepted, &tle);
    let (committed_terminal, committed_chain) = terminal_page(&committed);
    let committed_anchor = checkpoint_of(&committed_chain[0]);
    let source = ScriptedSource::with_pages(vec![committed_terminal.clone()]);
    let mut context = capture(newcomer);
    register(
        state_args(
            Some(directory.path().join("second.state.nrt")),
            Some(committed_anchor.clone()),
        ),
        &key,
    )
    .execute(&mut context, &source)
    .expect("idempotent register");
    assert!(context.submitted.is_empty());
    assert_eq!(context.printed.len(), 1);
    assert_eq!(context.printed[0]["registered"].as_bool(), Some(true));
    assert_eq!(context.printed[0]["submitted"].as_bool(), Some(false));
    assert_eq!(
        context.printed[0]["participant_hash"].as_str(),
        Some(hex::encode(participant_hash).as_str())
    );

    // Another key file cannot re-register the account.
    let other_key = directory.path().join("other.key");
    files::load_or_create_key_file_with(&other_key, || Ok(seed(0x99))).expect("other key");
    let source = ScriptedSource::with_pages(vec![committed_terminal]);
    let mut context = capture(newcomer);
    let conflict = register(state_args(None, Some(committed_anchor.clone())), &other_key)
        .execute(&mut context, &source)
        .expect_err("conflicting key file");
    assert!(format!("{conflict:#}").contains("key file does not hold the seed"));
    assert!(context.submitted.is_empty());
}

#[cfg(unix)]
#[test]
fn cast_locks_the_choice_and_submits_one_record_for_the_seat() {
    let (RegisteredJurors { tle, jurors, .. }, frozen, frozen_context) = frozen_jurors();
    let (terminal, chain) = terminal_page(&frozen_context);
    let anchor = checkpoint_of(&chain[0]);
    // The juror at seat 0, so Core can accept the submitted chunk directly.
    let (juror_index, seat) = jurors
        .iter()
        .enumerate()
        .map(|(index, (authority, _))| {
            (
                index,
                survivor_seat(&frozen_context, authority).expect("seat"),
            )
        })
        .find(|(_, seat)| seat.index == 0)
        .expect("a juror holds seat 0");
    let juror_byte = 0x51 + u8::try_from(juror_index).expect("small index");
    let (authority, juror_seed) = &jurors[juror_index];
    let directory = tempfile::tempdir().expect("juror directory");
    let key = directory.path().join("juror.key");
    files::load_or_create_key_file_with(&key, || Ok(seed(0x61 + juror_byte - 0x51)))
        .expect("key file");
    let record_out = directory.path().join("record.hex");
    let cast =
        |choice, init: Option<SumeragiFinalityCheckpoint>, record_out: Option<PathBuf>| CastArgs {
            ballot_attempt_id: fixture_ballot_id(),
            choice,
            files: BallotFilesArgs {
                key_file: key.clone(),
                state: state_args(None, init),
            },
            record_out,
            wait_secs: 0,
        };

    let source = ScriptedSource::with_pages(vec![terminal.clone()]).with_attempt(attempt_with(
        BallotAttemptStatusV1::TimedCommitment,
        Some(3),
        Some(0),
    ));
    let mut context = capture(juror_byte).text();
    cast(
        BallotChoiceArg::Approve,
        Some(anchor.clone()),
        Some(record_out.clone()),
    )
    .execute(&mut context, &source)
    .expect("cast");
    let expected = ballot_from_seed(
        &frozen_context,
        authority,
        juror_seed,
        BallotChoiceArg::Approve,
    )
    .expect("expected ballot");
    let transition = context.single_transition();
    assert_eq!(
        transition.governance_attempt_id,
        GovernanceAttemptId::new(binding(11))
    );
    let ParliamentLifecycleTransitionV1::FreezeTimedOvnCorpus(payload) = &transition.transition
    else {
        panic!("expected a corpus chunk")
    };
    assert_eq!(payload.ballot_attempt_id, fixture_ballot_id());
    assert_eq!(payload.ballot_records, vec![expected.clone()]);
    assert!(context.lines[0].contains("casting survivor seat 0 of 3"));
    assert_eq!(
        files::read_public_record(&record_out, TIMED_OVN_BALLOT_RECORD_BYTES_V1)
            .expect("exported record"),
        expected
    );
    assert_eq!(
        files::read_choice_lock(&key, fixture_ballot_id().as_bytes(), &seat.participant_hash)
            .expect("lock"),
        Some(BallotChoiceArg::Approve)
    );
    assert_eq!(
        *source.attempt_requests.borrow(),
        vec![GovernanceAttemptId::new(binding(11))]
    );
    let accepted = frozen
        .seal_ballots(payload.ballot_records.clone(), &tle)
        .expect("Core accepts the submitted ballot");
    assert_eq!(accepted.accepted_ballot_prefix_count(), Some(1));

    // Another choice for the same seat is refused before any Torii read.
    let source = ScriptedSource::default();
    let mut context = capture(juror_byte);
    let refused = cast(BallotChoiceArg::Reject, None, None)
        .execute(&mut context, &source)
        .expect_err("second choice");
    assert!(format!("{refused:#}").contains("reveal both choices"));
    assert!(source.proof_requests.borrow().is_empty());
    assert!(context.submitted.is_empty());

    // Rerunning the same choice once accepted submits nothing and builds nothing.
    std::fs::remove_file(&record_out).expect("remove exported record");
    let source = ScriptedSource::with_pages(vec![page_from(&terminal, &chain, chain.len() - 1)])
        .with_attempt(attempt_with(
            BallotAttemptStatusV1::TimedCommitment,
            Some(3),
            Some(1),
        ));
    let mut context = capture(juror_byte);
    cast(BallotChoiceArg::Approve, None, Some(record_out.clone()))
        .execute(&mut context, &source)
        .expect("already accepted");
    assert!(context.submitted.is_empty());
    assert_eq!(context.printed[0]["accepted"].as_bool(), Some(true));
    assert_eq!(context.printed[0]["submitted"].as_bool(), Some(false));
    assert!(!record_out.exists(), "an accepted seat builds no ballot");
    assert_eq!(
        *source.proof_requests.borrow(),
        vec![checkpoint_of(chain.last().expect("tip"))],
        "the rerun starts from the promoted checkpoint"
    );
}

#[cfg(unix)]
#[test]
fn dropout_checks_the_public_or_authenticated_context_without_the_key() {
    let RegisteredJurors {
        tle,
        lifecycle,
        jurors,
        ..
    } = register_jurors();
    let closed = lifecycle
        .close_registration(&tle)
        .expect("close registration");
    let closed_context = casting_context(&closed, &tle);
    let dropout = |key_file: Option<PathBuf>, state: BallotStateArgs| DropoutArgs {
        ballot_attempt_id: fixture_ballot_id(),
        key_file,
        state,
    };

    let source = ScriptedSource::default().with_public(&closed_context);
    let mut context = capture(0x52).text();
    dropout(None, state_args(None, None))
        .execute(&mut context, &source)
        .expect("public dropout");
    let ParliamentLifecycleTransitionV1::RecordBallotDropout(payload) =
        &context.single_transition().transition
    else {
        panic!("expected a dropout")
    };
    assert_eq!(payload.ballot_attempt_id, fixture_ballot_id());
    assert!(context.lines[0].contains("public casting context"));
    assert_eq!(*source.public_requests.borrow(), vec![fixture_ballot_id()]);
    assert!(source.proof_requests.borrow().is_empty());
    closed
        .clone()
        .record_dropout(
            parliament_ballot_participant_hash_v1(fixture_ballot_id(), &jurors[1].0),
            &tle,
        )
        .expect("Core records the dropout");

    // A lost key file still locates the state file; the key is never read.
    let (terminal, chain) = terminal_page(&closed_context);
    let directory = tempfile::tempdir().expect("juror directory");
    let lost_key = directory.path().join("lost.key");
    let source = ScriptedSource::with_pages(vec![terminal]);
    let mut context = capture(0x52).text();
    dropout(
        Some(lost_key.clone()),
        state_args(None, Some(checkpoint_of(&chain[0]))),
    )
    .execute(&mut context, &source)
    .expect("authenticated dropout");
    assert!(context.lines[0].contains("consensus-authenticated casting context"));
    assert_eq!(context.submitted.len(), 1);
    assert!(!lost_key.exists());
    assert!(files::default_state_path(&lost_key).exists());
    assert!(source.public_requests.borrow().is_empty());

    let source = ScriptedSource::default().with_public(&closed_context);
    let mut context = capture(0x5A);
    let stranger = dropout(None, state_args(None, None))
        .execute(&mut context, &source)
        .expect_err("unregistered account");
    assert!(format!("{stranger:#}").contains("not registered"));
    assert!(context.submitted.is_empty());
}

#[cfg(unix)]
#[test]
fn relay_submits_the_chunk_that_continues_the_accepted_prefix() {
    let (RegisteredJurors { tle, jurors, .. }, frozen, frozen_context) = frozen_jurors();
    let directory = tempfile::tempdir().expect("record directory");
    let mut by_seat = BTreeMap::new();
    let mut paths = Vec::new();
    for (index, (authority, juror_seed)) in jurors.iter().enumerate() {
        let record = ballot_from_seed(
            &frozen_context,
            authority,
            juror_seed,
            BallotChoiceArg::Abstain,
        )
        .expect("ballot");
        let path = directory.path().join(format!("{index}.hex"));
        files::write_public_record(&path, &record).expect("export record");
        by_seat.insert(
            survivor_seat(&frozen_context, authority)
                .expect("seat")
                .index,
            record,
        );
        paths.push(path);
    }
    let relay = |records: Vec<PathBuf>| RelayArgs {
        ballot_attempt_id: fixture_ballot_id(),
        records,
    };

    let source = ScriptedSource::default()
        .with_public(&frozen_context)
        .with_attempt(attempt_with(
            BallotAttemptStatusV1::TimedCommitment,
            Some(3),
            Some(1),
        ));
    let mut context = capture(0x5A);
    relay(paths.clone())
        .execute(&mut context, &source)
        .expect("relay");
    let ParliamentLifecycleTransitionV1::FreezeTimedOvnCorpus(payload) =
        &context.single_transition().transition
    else {
        panic!("expected a corpus chunk")
    };
    assert_eq!(
        payload.ballot_records,
        vec![by_seat[&1].clone(), by_seat[&2].clone()]
    );
    assert_eq!(
        *source.attempt_requests.borrow(),
        vec![GovernanceAttemptId::new(binding(11))]
    );
    let sealed = frozen
        .seal_ballots(vec![by_seat[&0].clone()], &tle)
        .and_then(|open| open.seal_ballots(payload.ballot_records.clone(), &tle))
        .expect("Core accepts the relayed chunk");
    assert!(matches!(sealed, TimedOvnLifecycleStateV1::Sealed(_)));

    let source = ScriptedSource::default()
        .with_public(&frozen_context)
        .with_attempt(attempt_with(
            BallotAttemptStatusV1::AwaitingRelease,
            Some(3),
            Some(3),
        ));
    let mut context = capture(0x5A);
    assert!(
        format!(
            "{:#}",
            relay(paths)
                .execute(&mut context, &source)
                .expect_err("sealed ballot")
        )
        .contains("no longer accepts")
    );
    assert!(context.submitted.is_empty());

    let source = ScriptedSource::default();
    let too_many = relay(vec![
        PathBuf::from("/nonexistent.hex");
        MAX_RELAY_RECORD_FILES + 1
    ])
    .execute(&mut capture(0x5A), &source)
    .expect_err("too many files");
    assert!(format!("{too_many:#}").contains("at most"));
    assert!(source.public_requests.borrow().is_empty());
}

#[cfg(unix)]
#[test]
fn status_reports_custody_and_resolves_the_attempt_from_the_ballot() {
    let RegisteredJurors {
        tle,
        lifecycle,
        jurors,
        ..
    } = register_jurors();
    let registered = casting_context(&lifecycle, &tle);
    let directory = tempfile::tempdir().expect("juror directory");
    let key = directory.path().join("juror.key");
    files::load_or_create_key_file_with(&key, || Ok(seed(0x61))).expect("key file");
    let participant_hash = parliament_ballot_participant_hash_v1(fixture_ballot_id(), &jurors[0].0);
    files::lock_choice(
        &key,
        fixture_ballot_id().as_bytes(),
        &participant_hash,
        BallotChoiceArg::Abstain,
    )
    .expect("lock");
    let status = |governance_attempt_id, key_file: Option<PathBuf>| StatusArgs {
        governance_attempt_id,
        ballot_attempt_id: Some(fixture_ballot_id()),
        key_file,
        state_file: None,
    };

    let source = ScriptedSource::default()
        .with_public(&registered)
        .with_attempt(attempt_with(
            BallotAttemptStatusV1::Registration,
            None,
            None,
        ));
    let mut context = capture(0x51);
    status(None, Some(key.clone()))
        .execute(&mut context, &source)
        .expect("status by ballot");
    let document = &context.printed[0];
    assert_eq!(
        document["governance_attempt_id"].as_str(),
        Some(GovernanceAttemptId::new(binding(11)).to_hex().as_str())
    );
    assert_eq!(document["current_height"].as_u64(), Some(37));
    assert_eq!(document["key_file_present"].as_bool(), Some(true));
    assert_eq!(document["state_file_present"].as_bool(), Some(false));
    let entry = &document["ballots"][0];
    assert_eq!(entry["registered"].as_bool(), Some(true));
    assert_eq!(entry["key_file_matches_registration"].as_bool(), Some(true));
    assert_eq!(entry["choice_lock"].as_str(), Some("abstain"));
    assert_eq!(
        *source.public_requests.borrow(),
        vec![fixture_ballot_id(), fixture_ballot_id()],
        "one read resolves the attempt, one reports participation"
    );
    assert_eq!(
        *source.attempt_requests.borrow(),
        vec![GovernanceAttemptId::new(binding(11))]
    );

    let source = ScriptedSource::default()
        .with_public(&registered)
        .with_attempt(attempt_with(
            BallotAttemptStatusV1::Registration,
            None,
            None,
        ));
    let absent_key = directory.path().join("absent.key");
    let mut context = capture(0x51).text();
    status(
        Some(GovernanceAttemptId::new(binding(11))),
        Some(absent_key.clone()),
    )
    .execute(&mut context, &source)
    .expect("status by attempt");
    assert_eq!(
        *source.public_requests.borrow(),
        vec![fixture_ballot_id()],
        "a named attempt needs no resolution read"
    );
    assert!(
        context.lines[0].contains("registered=true"),
        "{}",
        context.lines[0]
    );
    assert!(context.lines[0].contains("choice_lock=-"));
    assert!(!absent_key.exists(), "status never creates a key file");
}

// ---------------------------------------------------------------------------
// The Client-backed source and the `run` entry points
// ---------------------------------------------------------------------------

/// The public casting-context response Torii serves for `context`.
fn public_context_response(
    context: &ValidatedParliamentTimedOvnCastingContextArchiveV1,
) -> iroha_torii_shared::parliament_api::ParliamentTimedOvnCastingContextResponseV1 {
    use base64::Engine as _;
    use iroha_data_model::governance::types::{BodyInstanceId, ProposalContentId};
    use iroha_torii_shared::parliament_api::{
        PARLIAMENT_API_VERSION_V1, ParliamentTimedOvnCastingContextResponseV1,
        ParliamentTimedOvnCastingPhaseProjectionV1, ParliamentTimedOvnReleaseIdentityProjectionV1,
        ParliamentTimedOvnSessionProjectionV1, ParliamentTleAdaptiveDealerCommitmentV1,
        ParliamentTleAdaptivePublicShareV1, ParliamentTleKeySessionBindingV1,
    };

    let archive = context.archive();
    let session = archive.session();
    let tle = archive.tle_key_session();
    ParliamentTimedOvnCastingContextResponseV1 {
        version: PARLIAMENT_API_VERSION_V1,
        current_height: archive.finalized_height(),
        phase: match archive.phase() {
            ParliamentTimedOvnCastingPhaseV1::Registered => {
                ParliamentTimedOvnCastingPhaseProjectionV1::Registered
            }
            ParliamentTimedOvnCastingPhaseV1::RegistrationClosed => {
                ParliamentTimedOvnCastingPhaseProjectionV1::RegistrationClosed
            }
            ParliamentTimedOvnCastingPhaseV1::SurvivorsFrozen => {
                ParliamentTimedOvnCastingPhaseProjectionV1::SurvivorsFrozen
            }
        },
        session: ParliamentTimedOvnSessionProjectionV1 {
            network_id: session.network_id,
            proposal_content_id: ProposalContentId::new(session.proposal_content_id),
            governance_attempt_id: GovernanceAttemptId::new(session.governance_attempt_id),
            body_instance_id: BodyInstanceId::new(session.body_instance_id),
            ballot_attempt_id: BallotAttemptId::new(session.ballot_attempt_id),
            parameter_hash: session.parameter_hash,
            tle_key_session_id: session.tle_key_session_id,
            tle_key_transcript_hash: session.tle_key_transcript_hash,
            tle_master_public_key: session.tle_master_public_key,
        },
        registration_opened_at_finalized_height: archive.registration_opened_at_finalized_height(),
        target_finalized_height: archive.target_finalized_height(),
        tle_key_session: ParliamentTleKeySessionBindingV1 {
            version: tle.version,
            key_session_id: tle.key_session_id,
            network_id: tle.network_id,
            roster_hash: tle.roster_hash,
            committee_size: tle.committee_size,
            threshold: tle.threshold,
            generator_h: tle.generator_h,
            generator_v: tle.generator_v,
            qualified_dealers: tle.qualified_dealers.clone(),
            qualified_dealer_commitments: tle
                .qualified_dealer_commitments
                .iter()
                .map(|dealer| ParliamentTleAdaptiveDealerCommitmentV1 {
                    dealer_index: dealer.dealer_index,
                    coefficient_commitments: dealer.coefficient_commitments.clone(),
                    constant_pok_commitment: dealer.constant_pok_commitment,
                    constant_pok_response: dealer.constant_pok_response,
                })
                .collect(),
            dkg_event_hash: tle.dkg_event_hash,
            group_public_key: tle.group_public_key,
            public_shares: tle
                .public_shares
                .iter()
                .map(|share| ParliamentTleAdaptivePublicShareV1 {
                    index: share.index,
                    participant_hash: share.participant_hash,
                    public_key_share: share.public_key_share,
                })
                .collect(),
            transcript_hash: tle.transcript_hash,
        },
        registration_records_hex: archive
            .registration_records()
            .iter()
            .map(hex::encode)
            .collect(),
        survivor_participant_hashes: archive.survivor_participant_hashes().map(<[_]>::to_vec),
        release_identity: archive.release_identity().map(|identity| {
            ParliamentTimedOvnReleaseIdentityProjectionV1 {
                tle_key_session_id: identity.tle_key_session_id,
                governance_attempt_id: GovernanceAttemptId::new(identity.governance_attempt_id),
                body_instance_id: BodyInstanceId::new(identity.body_instance_id),
                ballot_attempt_id: BallotAttemptId::new(identity.ballot_attempt_id),
                survivor_corpus_root: identity.survivor_corpus_root,
                no_recovery_root: identity.no_recovery_root,
                target_finalized_height: identity.target_finalized_height,
                parameter_hash: identity.parameter_hash,
            }
        }),
        archive_norito_base64: BASE64_STANDARD
            .encode(archive.to_canonical_bytes_v1().expect("canonical archive")),
    }
}

/// An attempt read response Torii serves for a canonical attempt id.
fn attempt_response(
    governance_attempt_id: GovernanceAttemptId,
    proposal_content_id: iroha_data_model::governance::types::ProposalContentId,
    snapshot: &AttemptSnapshot,
) -> iroha_torii_shared::parliament_api::ParliamentAttemptReadResponseV1 {
    use iroha_data_model::governance::types::{
        GovernanceAttemptStatusV1, GovernanceAttemptV1, GovernanceStageV1, RiskTierV1,
    };
    iroha_torii_shared::parliament_api::ParliamentAttemptReadResponseV1 {
        version: iroha_torii_shared::parliament_api::PARLIAMENT_API_VERSION_V1,
        current_height: snapshot.current_height,
        attempt: GovernanceAttemptV1 {
            id: governance_attempt_id,
            proposal_content_id,
            sequence: 0,
            risk_tier: RiskTierV1::Constitutional,
            stage: GovernanceStageV1::PolicyJury,
            status: GovernanceAttemptStatusV1::Active,
        },
        policy_version: 1,
        required_bodies: Vec::new(),
        body_states: snapshot.body_states.clone(),
        certificate: None,
        terminal_height: None,
        execution_failure_root: None,
        superseding_head: None,
        state_payload_hex: hex::encode(norito::to_bytes(&1_u64).expect("reducer frame")),
    }
}

#[test]
fn client_source_reads_public_contexts_and_attempts_from_torii() {
    let RegisteredJurors { tle, lifecycle, .. } = register_jurors();
    let registered = casting_context(&lifecycle, &tle);
    let proposal_content_id =
        iroha_data_model::governance::types::ProposalContentId::new(binding(10));
    let canonical_attempt = GovernanceAttemptId::derive_v1(proposal_content_id, 0);
    let snapshot = attempt_with(BallotAttemptStatusV1::Registration, None, None);
    let (url, requests, server) = spawn_stub_server(vec![
        (
            "application/json",
            norito::json::to_vec(&public_context_response(&registered)).expect("context JSON"),
        ),
        (
            "application/json",
            norito::json::to_vec(&attempt_response(
                canonical_attempt,
                proposal_content_id,
                &snapshot,
            ))
            .expect("attempt JSON"),
        ),
    ]);
    let mut config = crate::fallback_config();
    config.network_id = fixture_network_id();
    config.torii_api_url = url;
    let client = Client::builder(config).build().expect("client");

    let archive =
        BallotSource::public_casting_context(&client, fixture_ballot_id()).expect("context");
    assert_eq!(archive.archive(), registered.archive());
    let attempt = BallotSource::attempt(&client, canonical_attempt).expect("attempt");
    assert_eq!(attempt.current_height, snapshot.current_height);
    assert_eq!(attempt.body_states, snapshot.body_states);
    server.join().expect("join server");
    let lines = requests
        .into_iter()
        .map(|(line, _)| line)
        .collect::<Vec<_>>();
    assert!(lines[0].starts_with("get ") && lines[0].contains(&fixture_ballot_id().to_hex()));
    assert!(lines[1].starts_with("get ") && lines[1].contains(&canonical_attempt.to_hex()));
}

/// A Torii URL whose port refuses connections.
fn closed_torii() -> Url {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address");
    drop(listener);
    Url::parse(&format!("http://{address}")).expect("closed URL")
}

#[cfg(unix)]
#[test]
fn run_entry_points_reach_the_configured_torii() {
    use crate::Run as _;
    // `register` and `dropout` complete through the configured client alone.
    let RegisteredJurors { tle, lifecycle, .. } = register_jurors();
    let registered = casting_context(&lifecycle, &tle);
    let (terminal, chain) = terminal_page(&registered);
    let anchor = checkpoint_of(&chain[0]);
    let directory = tempfile::tempdir().expect("juror directory");
    let key = directory.path().join("juror.key");
    let (url, requests, server) =
        spawn_norito_server(vec![norito::to_bytes(&terminal).expect("encode page")]);
    let mut context = capture(0x54).with_torii(url);
    RegisterArgs {
        ballot_attempt_id: fixture_ballot_id(),
        files: BallotFilesArgs {
            key_file: key.clone(),
            state: state_args(None, Some(anchor.clone())),
        },
    }
    .run(&mut context)
    .expect("register through the client");
    server.join().expect("join server");
    assert!(requests.recv().expect("request").0.starts_with("post "));
    assert!(matches!(
        context.single_transition().transition,
        ParliamentLifecycleTransitionV1::RegisterBallotParticipant(_)
    ));

    let closed = lifecycle
        .close_registration(&tle)
        .expect("close registration");
    let closed_context = casting_context(&closed, &tle);
    let (closed_terminal, closed_chain) = terminal_page(&closed_context);
    let (url, _requests, server) = spawn_norito_server(vec![
        norito::to_bytes(&closed_terminal).expect("encode page"),
    ]);
    let mut context = capture(0x51).with_torii(url);
    DropoutArgs {
        ballot_attempt_id: fixture_ballot_id(),
        key_file: None,
        state: state_args(
            Some(directory.path().join("dropout.state.nrt")),
            Some(checkpoint_of(&closed_chain[0])),
        ),
    }
    .run(&mut context)
    .expect("dropout through the client");
    server.join().expect("join server");
    assert!(matches!(
        context.single_transition().transition,
        ParliamentLifecycleTransitionV1::RecordBallotDropout(_)
    ));

    // Every other entry point reports the Torii read it could not make.
    let unreachable = |command: BallotCommand| {
        let mut context = capture(0x51).with_torii(closed_torii());
        let error = command.run(&mut context).expect_err("unreachable Torii");
        assert!(context.submitted.is_empty());
        format!("{error:#}")
    };
    let record = directory.path().join("record.hex");
    files::write_public_record(&record, &vec![0x5C; TIMED_OVN_BALLOT_RECORD_BYTES_V1])
        .expect("record");
    assert!(
        unreachable(BallotCommand::Cast(Box::new(CastArgs {
            ballot_attempt_id: fixture_ballot_id(),
            choice: BallotChoiceArg::Approve,
            files: BallotFilesArgs {
                key_file: key.clone(),
                state: state_args(
                    Some(directory.path().join("cast.state.nrt")),
                    Some(anchor.clone())
                ),
            },
            record_out: None,
            wait_secs: 0,
        })))
        .contains("failed to fetch the Parliament casting proof")
    );
    assert!(
        unreachable(BallotCommand::Relay(RelayArgs {
            ballot_attempt_id: fixture_ballot_id(),
            records: vec![record],
        }))
        .contains("failed to read the Parliament casting context")
    );
    assert!(
        unreachable(BallotCommand::Status(StatusArgs {
            governance_attempt_id: Some(GovernanceAttemptId::new(binding(11))),
            ballot_attempt_id: None,
            key_file: None,
            state_file: None,
        }))
        .contains("failed to read the Parliament attempt")
    );
    assert!(
        unreachable(BallotCommand::Dropout(DropoutArgs {
            ballot_attempt_id: fixture_ballot_id(),
            key_file: None,
            state: state_args(None, None),
        }))
        .contains("failed to read the Parliament casting context")
    );
}
