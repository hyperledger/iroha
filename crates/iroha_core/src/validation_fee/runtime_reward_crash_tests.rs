//! Real process termination at reward archive seams, strict disk reopening and certified replay.
//!
//! The explicit component bootstrap is reconstructed independently in each process.
//! These tests do not qualify genesis governance or loss of the kernel's disk cache.

use super::*;
use crate::query::native_context_archive::process_crash::{self, Boundary};
use iroha_crypto::HashOf;
use iroha_data_model::{block::BlockHeader, transaction::SignedTransaction};
use std::{
    fs::{self, File},
    io::Write as _,
    path::Path,
    process::Command,
    sync::Arc,
    time::{Duration, Instant},
};

const EXACT: &str = "validation_fee::tests::runtime_wrapper_tests::reward_tests::crash_tests::process_crashes_preserve_funding_entitlements_claims_and_checkpoints";
const MODE: &str = "IROHA_REWARD_CRASH_TEST_MODE";
const CASE: &str = "IROHA_REWARD_CRASH_TEST_CASE";
const ROOT: &str = "IROHA_REWARD_CRASH_TEST_ROOT";
// Both modes execute real certificates; recovery also rebuilds and replays twice.
// A contended host took 211 seconds to reach an intended crash, while recovery
// completed in 79 seconds. Keep a finite bound without removing authenticated work.
const CHILD_TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Transition {
    Funding,
    FirstCredit,
    NominatorClaim,
    Checkpoint,
}

fn cases() -> Vec<(Transition, Boundary)> {
    [
        Transition::Funding,
        Transition::FirstCredit,
        Transition::NominatorClaim,
        Transition::Checkpoint,
    ]
    .into_iter()
    .flat_map(|transition| {
        [
            Boundary::BeforeWrite,
            Boundary::StageSynced,
            Boundary::CanonicalSynced,
            Boundary::Complete,
        ]
        .into_iter()
        .map(move |boundary| (transition, boundary))
    })
    .collect()
}

#[test]
fn process_crashes_preserve_funding_entitlements_claims_and_checkpoints() {
    if let Some(mode) = std::env::var_os(MODE) {
        let case = std::env::var(CASE).unwrap().parse::<usize>().unwrap();
        let root = std::path::PathBuf::from(std::env::var_os(ROOT).unwrap());
        let (transition, boundary) = cases()[case];
        std::thread::Builder::new()
            .name("reward-crash-recovery".to_owned())
            .stack_size(32 * 1024 * 1024)
            .spawn(move || match mode.to_str().unwrap() {
                "crash" => crash(&root, transition, boundary),
                "recover" => recover(&root, transition, boundary),
                other => panic!("unknown disposable child mode: {other}"),
            })
            .unwrap()
            .join()
            .unwrap();
        return;
    }
    for (case, (transition, boundary)) in cases().into_iter().enumerate() {
        let directory = tempfile::Builder::new()
            .prefix("iroha-reward-process-crash-")
            .tempdir()
            .unwrap();
        let root = fs::canonicalize(directory.path()).unwrap();
        for mode in ["crash", "recover"] {
            let (status, stdout, stderr) = run_child(&root, case, mode);
            let expected = if mode == "crash" {
                process_crash::EXIT_CODE
            } else {
                0
            };
            assert_eq!(
                status.code(),
                Some(expected),
                "{transition:?}/{boundary:?}/{mode} failed\nstdout:\n{}\nstderr:\n{}",
                stdout,
                stderr,
            );
            if mode == "recover" {
                assert!(stdout.contains("test result: ok. 1 passed; 0 failed;"));
            }
        }
        eprintln!("qualified process crash: {transition:?}/{boundary:?}");
    }
}

fn run_child(root: &Path, case: usize, mode: &str) -> (std::process::ExitStatus, String, String) {
    let started = Instant::now();
    let stdout_path = root.join(format!("{mode}.stdout.log"));
    let stderr_path = root.join(format!("{mode}.stderr.log"));
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([EXACT, "--exact", "--nocapture", "--test-threads=1"])
        .env(MODE, mode)
        .env(CASE, case.to_string())
        .env(ROOT, root)
        // All child temporaries belong to this disposable parent directory,
        // including the Kura whose destructor process::exit deliberately skips.
        .env("TMPDIR", root)
        .stdout(File::create(&stdout_path).unwrap())
        .stderr(File::create(&stderr_path).unwrap())
        .spawn()
        .expect("run only this disposable reward test subprocess");
    let deadline = started + CHILD_TIMEOUT;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            // This handle belongs only to the exact disposable test child
            // created above. Cargo, rustc, peers and other sessions are untouched.
            child
                .kill()
                .expect("terminate our timed-out disposable test child");
            child.wait().unwrap();
            panic!(
                "reward crash child {case}/{mode} exceeded its {}-second deadline\nstdout:\n{}\nstderr:\n{}",
                CHILD_TIMEOUT.as_secs(),
                fs::read_to_string(&stdout_path).unwrap(),
                fs::read_to_string(&stderr_path).unwrap(),
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    eprintln!(
        "reward crash child completed: case={case} mode={mode} elapsed={:.3}s status={status}",
        started.elapsed().as_secs_f64()
    );
    (
        status,
        fs::read_to_string(stdout_path).unwrap(),
        fs::read_to_string(stderr_path).unwrap(),
    )
}

fn expected(seed: u8) -> Quantity {
    Quantity::from(match seed {
        2 => 2_u32,
        3 => 3,
        4 => 5,
        5 => 10,
        _ => panic!("unknown reward owner"),
    })
}

fn signed_claim(fixture: &ScheduledRewardFixture, seed: u8) -> SignedTransaction {
    let next = fixture.chain.height() + 1;
    let claimant = account(seed);
    let fee_claim = crate::validation_fee_rewards::fee_reward_claim_plan(
        &fixture.chain.state().view().world,
        next,
        &claimant,
        LaneId::SINGLE,
    )
    .unwrap()
    .expect("native automatic entitlement survives without a manual payout list");
    assert_eq!(fee_claim.amount, expected(seed));
    fixture.chain.sign(
        &key_pair(seed),
        [ClaimPublicLaneRewards {
            lane_id: LaneId::SINGLE,
            account: claimant,
            claim_plan: PublicLaneRewardClaimPlanV1 {
                network_scope: PublicLaneMonetaryScopeV1::Network(fixture.chain.network_id()),
                valid_until_height: next,
                fee_claim,
            },
        }
        .into()],
        next_time(fixture),
    )
}

fn next_time(fixture: &ScheduledRewardFixture) -> u64 {
    CONVERSION_TIME + (fixture.chain.height() + 1) * 1_000
}

fn advance(fixture: &mut ScheduledRewardFixture) {
    fixture.chain.commit_at(next_time(fixture), Vec::new());
}

fn claim(fixture: &mut ScheduledRewardFixture, seed: u8) {
    let transaction = signed_claim(fixture, seed);
    assert_eq!(
        fixture
            .chain
            .commit_at(next_time(fixture), vec![transaction]),
        vec![true]
    );
}

fn crash(root: &Path, transition: Transition, boundary: Boundary) {
    let started = Instant::now();
    let phase = |name: &str| {
        eprintln!(
            "reward crash phase: {transition:?}/{boundary:?}/crash {name} elapsed={:.3}s",
            started.elapsed().as_secs_f64()
        );
    };
    phase("reconstructing component prefix");
    let mut fixture = prepare_scheduled_reward_fixture(false, true);
    phase("component prefix reconstructed");
    let prefix_hash = fixture.prefix_hash;
    let transactions = match transition {
        Transition::Funding => Vec::new(),
        Transition::FirstCredit => {
            advance(&mut fixture);
            Vec::new()
        }
        Transition::NominatorClaim | Transition::Checkpoint => {
            advance(&mut fixture);
            advance(&mut fixture);
            advance(&mut fixture);
            if transition == Transition::NominatorClaim {
                vec![signed_claim(&fixture, 3)]
            } else {
                for seed in [3, 2, 4, 5] {
                    claim(&mut fixture, seed);
                }
                Vec::new()
            }
        }
    };
    phase("reward transition predecessors committed");
    let store = fixture.chain.kura().store_root();
    assert!(store.starts_with(root));
    let proposal = fixture
        .chain
        .proposal(Some(next_time(&fixture)), transactions);
    let mut pending = fixture
        .chain
        .begin_proposal(proposal, Default::default())
        .unwrap();
    pending
        .prepare_publication_for_inspection(crate::sumeragi::test_chain::Signers::Quorum)
        .unwrap();
    phase("original durable publication prepared");
    let (height, hash) = pending
        .inspect_prepared(|source| {
            (
                source.block.as_ref().header().height().get(),
                source.block.as_ref().hash(),
            )
        })
        .unwrap();
    let bytes = norito::to_bytes(&(
        store.to_str().unwrap().to_owned(),
        height,
        hash,
        prefix_hash,
    ))
    .unwrap();
    let mut manifest = File::create(root.join("original.norito")).unwrap();
    manifest.write_all(&bytes).unwrap();
    manifest.sync_all().unwrap();
    File::open(root).unwrap().sync_all().unwrap();
    process_crash::arm(height, hash, boundary);
    phase("publishing at armed archive boundary");
    pending
        .publish(crate::sumeragi::test_chain::Signers::Quorum)
        .unwrap();
    panic!("the exact armed process-crash boundary was not reached");
}

fn reopen(root: &Path) -> Arc<crate::kura::Kura> {
    use iroha_config::{
        base::WithOrigin,
        kura::{FsyncMode, InitMode},
        parameters::{actual::Kura, defaults::kura as defaults},
    };
    let config = Kura {
        init_mode: InitMode::Strict,
        store_dir: WithOrigin::inline(root.to_path_buf()),
        max_disk_usage_bytes: defaults::MAX_DISK_USAGE_BYTES,
        blocks_in_memory: defaults::BLOCKS_IN_MEMORY,
        debug_output_new_blocks: false,
        fsync_mode: FsyncMode::Always,
        fsync_interval: defaults::FSYNC_INTERVAL,
        native_context_archive_max_bytes: defaults::NATIVE_CONTEXT_ARCHIVE_MAX_BYTES,
        history_checkpoint_cache_capacity: defaults::HISTORY_CHECKPOINT_CACHE_CAPACITY,
        block_hash_history_bytes: defaults::BLOCK_HASH_HISTORY_BYTES,
        transaction_history_bytes: defaults::TRANSACTION_HISTORY_BYTES,
        membership_storage: defaults::MEMBERSHIP_STORAGE_POLICY,
        fastpq_artifacts: defaults::FASTPQ_ARTIFACT_POLICY,
    };
    crate::kura::Kura::new_with_configured_lane_catalog(
        &config,
        &iroha_config::parameters::actual::LaneConfig::default(),
        &iroha_data_model::nexus::LaneCatalog::default(),
    )
    .expect("strict startup reopens the original crashed Kura files")
    .0
}

fn recover(root: &Path, transition: Transition, boundary: Boundary) {
    let started = Instant::now();
    let phase = |name: &str| {
        eprintln!(
            "reward crash phase: {transition:?}/{boundary:?}/recover {name} elapsed={:.3}s",
            started.elapsed().as_secs_f64()
        );
    };
    phase("checking original archive cut");
    let (path, height, hash, prefix_hash): (String, u64, HashOf<BlockHeader>, Hash) =
        norito::decode_canonical(&fs::read(root.join("original.norito")).unwrap()).unwrap();
    let store = fs::canonicalize(path).unwrap();
    assert!(store.starts_with(root));
    let (canonical_name, stage_name) = process_crash::record_names(height, hash);
    let canonical = store.join("native-contexts").join(canonical_name);
    let stage = store.join("native-contexts").join(stage_name);
    assert_eq!(
        canonical.exists(),
        matches!(boundary, Boundary::CanonicalSynced | Boundary::Complete)
    );
    assert_eq!(
        stage.exists(),
        matches!(boundary, Boundary::StageSynced | Boundary::CanonicalSynced)
    );
    #[cfg(unix)]
    if boundary == Boundary::CanonicalSynced {
        use std::os::unix::fs::MetadataExt as _;
        assert_eq!(
            fs::metadata(&canonical).unwrap().ino(),
            fs::metadata(&stage).unwrap().ino()
        );
        assert_eq!(fs::metadata(&canonical).unwrap().nlink(), 2);
    }
    let original_bytes = if canonical.exists() {
        Some(fs::read(&canonical).unwrap())
    } else if stage.exists() {
        Some(fs::read(&stage).unwrap())
    } else {
        None
    };
    let recovered = reopen(&store);
    assert_eq!(recovered.blocks_count(), usize::try_from(height).unwrap());
    phase("original Kura reopened strictly");
    let mut fixture = prepare_scheduled_reward_fixture(false, true);
    phase("first component prefix reconstructed");
    assert_eq!(
        fixture.prefix_hash, prefix_hash,
        "independently executed component prefix"
    );
    // A different original genesis must not enter the resource handoff.
    let foreign = CertifiedTestChain::start(crate::sumeragi::test_chain::TestChainConfig::new(
        crate::state::World::new(),
        EARNING_TIME - 40_000,
    ))
    .unwrap();
    assert!(
        fixture
            .chain
            .validate_reward_crash_prefix(foreign.kura())
            .unwrap_err()
            .contains("different original prefix")
    );
    drop(foreign);
    fixture
        .chain
        .validate_reward_crash_prefix(&recovered)
        .unwrap();
    phase("positive and negative original prefix checks passed");
    fixture.chain = fixture.chain.replay_reward_crash_store(recovered).unwrap();
    phase("first original store replay completed");
    assert_eq!(fixture.chain.height(), height);
    assert_eq!(fixture.chain.committed(height).block().hash(), hash);
    assert!(canonical.exists());
    assert!(
        !stage.exists(),
        "original partial archive stage is retired by certified replay"
    );
    if let Some(original_bytes) = original_bytes {
        assert_eq!(
            fs::read(&canonical).unwrap(),
            original_bytes,
            "immutable archive retry preserves every original byte"
        );
    }
    assert_cut(&fixture, transition);
    phase("recovered archive and reward cut assertions passed");
    if transition == Transition::Funding {
        advance(&mut fixture);
    }
    if matches!(transition, Transition::Funding | Transition::FirstCredit) {
        advance(&mut fixture);
    }
    for seed in [3, 2, 4, 5] {
        let pending = crate::validation_fee_rewards::pending_fee_reward(
            &fixture.chain.state().view().world,
            fixture.chain.height(),
            &account(seed),
            LaneId::SINGLE,
        )
        .unwrap();
        if pending.is_some() {
            claim(&mut fixture, seed);
        }
    }
    advance(&mut fixture);
    assert_cut(&fixture, Transition::Checkpoint);
    phase("all claims and history compaction assertions passed");
    // Replay the already-consumed original suffix again in a fresh owner. No
    // receipt can become a second entitlement or a second custody transfer.
    drop(fixture.chain);
    phase("reconstructing second independent component prefix");
    let mut second = prepare_scheduled_reward_fixture(false, true);
    phase("second component prefix reconstructed");
    second.chain = second
        .chain
        .replay_reward_crash_store(reopen(&store))
        .unwrap();
    phase("second original store replay completed");
    assert_cut(&second, Transition::Checkpoint);
    phase("second replay no double payment assertions passed");
}

fn assert_cut(fixture: &ScheduledRewardFixture, transition: Transition) {
    let view = fixture.chain.state().view();
    let key = |leaf: &str| validation_fee_reward_state_key(&fixture.binding, leaf).unwrap();
    let state: ValidationFeeRewardsState =
        norito::decode_canonical(view.world.smart_contract_state.get(&key("State")).unwrap())
            .unwrap();
    assert_eq!(
        state.next_allocation, 1,
        "one real funded conversion across every restart"
    );
    let claimed = match transition {
        Transition::NominatorClaim => 3,
        Transition::Checkpoint => 20,
        _ => 0,
    };
    assert_eq!(state.reserved_xor, (20 - claimed) * 1_000_000_000);
    assert_eq!(
        state.next_claim,
        match transition {
            Transition::NominatorClaim => 1,
            Transition::Checkpoint => 4,
            _ => 0,
        }
    );
    let pool = view
        .world
        .assets
        .get(&AssetId::new(
            fixture.pool.xor.clone(),
            fixture.pool.reward_pool.clone(),
        ))
        .map_or_else(Quantity::zero, |value| value.as_ref().clone());
    assert_eq!(pool, Quantity::from(u32::try_from(20 - claimed).unwrap()));
    let mut claimable = Quantity::zero();
    for seed in [2, 3, 4, 5] {
        let owner = account(seed);
        let paid = transition == Transition::Checkpoint
            || (transition == Transition::NominatorClaim && seed == 3);
        let principal = if matches!(seed, 2 | 5) {
            Quantity::from(100_u32)
        } else {
            Quantity::zero()
        };
        let balance = view
            .world
            .assets
            .get(&AssetId::new(fixture.pool.xor.clone(), owner.clone()))
            .map_or_else(Quantity::zero, |value| value.as_ref().clone());
        assert_eq!(
            balance,
            principal
                .checked_add(&if paid {
                    expected(seed)
                } else {
                    Quantity::zero()
                })
                .unwrap()
        );
        if matches!(seed, 2 | 5) {
            assert_eq!(
                view.world
                    .public_lane_stake_reserves
                    .get(&AssetId::new(fixture.pool.xor.clone(), owner.clone())),
                Some(&principal)
            );
        }
        if let Some(pending) = crate::validation_fee_rewards::pending_fee_reward(
            &view.world,
            fixture.chain.height(),
            &owner,
            LaneId::SINGLE,
        )
        .unwrap()
        {
            assert!(!paid);
            assert_eq!(pending.amount, expected(seed));
            claimable = claimable.checked_add(&pending.amount).unwrap();
        }
    }
    let expected_claimable = match transition {
        Transition::Funding | Transition::Checkpoint => 0_u32,
        Transition::FirstCredit => 10,
        Transition::NominatorClaim => 17,
    };
    assert_eq!(claimable, Quantity::from(expected_claimable));
    assert_eq!(
        view.world
            .smart_contract_state
            .get(&key("AllocationCursor"))
            .is_some(),
        matches!(transition, Transition::Funding | Transition::FirstCredit)
    );
    crate::state::validate_public_lane_stake_reserves_for_restore(&view.world).unwrap();
    if transition == Transition::Checkpoint {
        assert!(
            view.world
                .smart_contract_state
                .get(&key("HistoryCheckpoint"))
                .is_some()
        );
        for family in [
            "Allocation/",
            "Entitlement/",
            "Claim/",
            "ExposureSource/",
            "HistoryBalance/",
            "HistoryJournal/",
        ] {
            let prefix = key(family);
            assert!(
                !view
                    .world
                    .smart_contract_state
                    .range(prefix.clone()..)
                    .next()
                    .is_some_and(|(key, _)| key.as_ref().starts_with(prefix.as_ref())),
                "compacted rights must not keep {family}"
            );
        }
    }
}
