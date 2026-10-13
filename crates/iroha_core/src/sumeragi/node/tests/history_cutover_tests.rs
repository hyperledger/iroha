//! First-release history contract (`specs/first_release_history_cutover.md`).
//!
//! The current canonical genesis and its certified blocks replay from the bytes a store
//! persisted, with nothing else supplied. A history pinned by an earlier build replays to its
//! pinned State. The stored block wire is the single framed V1 layout. A store never replays
//! under another genesis: an incompatible change starts a new history from a fresh genesis and
//! a fresh store. Every retired store artifact of the inventory still stops Strict startup.

use std::{
    num::NonZeroUsize,
    path::{Path, PathBuf},
};

use iroha_config::{
    kura::{FsyncMode, InitMode},
    parameters::{
        actual::{Kura as KuraConfig, LaneConfig as LaneGeometry},
        defaults,
    },
};
use iroha_config_base::WithOrigin;
use iroha_data_model::block::{SharedSignedBlock, decode_framed_signed_block};
use norito::json::Value;
use sha2::{Digest as _, Sha256};

use super::*;

/// The pinned history: frames written by an earlier build and the State they replay to.
const PINNED_HISTORY: &str = "fixtures/core/first_release_history";
/// Format tag of the pinned history manifest.
const PINNED_FORMAT: &str = "iroha.first_release_history.pinned.v1";
/// The machine-readable inventory of the contract.
const INVENTORY: &str = "specs/first_release_history_cutover.json";
/// The refusal a restarted node relies on: the store's durable journal names another network.
const FOREIGN_STORE: &str = "lane storage journal belongs to another authenticated network";
/// Test-only developer toggle: the directory `capture_pinned_first_release_history` writes to.
/// Unset, the capture goes to a scratch directory and the tracked fixture is left alone.
const CAPTURE_DIR: &str = "IROHA_CAPTURE_FIRST_RELEASE_HISTORY_DIR";
/// What a failed replay of the pinned history means.
const PINNED_REPLAY_RULE: &str = "the pinned first-release history no longer replays to its pinned State. \
     This build is incompatible with existing histories: declare the cutover \
     (specs/first_release_history_cutover.md), then regenerate the fixture with \
     `IROHA_CAPTURE_FIRST_RELEASE_HISTORY_DIR=\"$PWD/fixtures/core/first_release_history\" \
     cargo test -p iroha_core --lib capture_pinned_first_release_history -- --ignored` \
     and record the new `history_sha256` in specs/first_release_history_cutover.json";

/// A path of the repository this crate is built from.
fn repository_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative)
}

/// The Strict configuration of a validator's on-disk block store.
fn store_config(root: &Path) -> KuraConfig {
    KuraConfig {
        init_mode: InitMode::Strict,
        store_dir: WithOrigin::inline(root.to_path_buf()),
        max_disk_usage_bytes: defaults::kura::MAX_DISK_USAGE_BYTES,
        blocks_in_memory: defaults::kura::BLOCKS_IN_MEMORY,
        history_checkpoint_cache_capacity: defaults::kura::HISTORY_CHECKPOINT_CACHE_CAPACITY,
        debug_output_new_blocks: false,
        fsync_mode: FsyncMode::Batched,
        fsync_interval: defaults::kura::FSYNC_INTERVAL,
        native_context_archive_max_bytes: defaults::kura::NATIVE_CONTEXT_ARCHIVE_MAX_BYTES,
        block_hash_history_bytes: defaults::kura::BLOCK_HASH_HISTORY_BYTES,
        transaction_history_bytes: defaults::kura::TRANSACTION_HISTORY_BYTES,
        membership_storage: defaults::kura::MEMBERSHIP_STORAGE_POLICY,
        fastpq_artifacts: defaults::kura::FASTPQ_ARTIFACT_POLICY,
    }
}

/// Open the store under `root` through Strict startup, or say why it was refused.
fn try_open_store(root: &Path) -> Result<Arc<Kura>, String> {
    Kura::open_test_kura_with_configured_lane_config(&store_config(root), &LaneGeometry::default())
        .map(|(kura, _)| kura)
        .map_err(|error| format!("{error}: {error:?}"))
}

/// Open (or reopen) the store under `root` through Strict startup.
fn open_store(root: &Path) -> Arc<Kura> {
    try_open_store(root).expect("Strict startup opens a first-release store")
}

/// Where a validator keeps its block store.
fn store_root(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join("kura")
}

/// One validator whose Kura is a real store under its directory.
fn stored_disk() -> Disk {
    let dir = tempfile::tempdir().expect("tempdir");
    Disk {
        kura: open_store(&store_root(&dir)),
        dir,
    }
}

/// The validators of `chain`, each on its own on-disk store.
fn stored_disks(chain: &Chain) -> Vec<Disk> {
    (0..chain.keys.len()).map(|_| stored_disk()).collect()
}

/// Wait until `handle` is the only owner left, failing with what is still held.
fn await_sole_owner<T>(handle: &Arc<T>, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Arc::strong_count(handle) > 1 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        Arc::strong_count(handle),
        1,
        "{what} is still held 30 s after its instance stopped"
    );
}

/// Drop every handle on a stopped validator's store and open it again from its directory: what
/// the new handle returns is what Strict startup reads back from disk, with no cached body.
fn reopen(disk: Disk) -> Disk {
    let Disk { kura, dir } = disk;
    await_sole_owner(&kura, "the Kura store of a stopped validator");
    drop(kura);
    Disk {
        kura: open_store(&store_root(&dir)),
        dir,
    }
}

/// The frames Kura persisted for blocks `1..=height`, read from the block data file.
fn persisted_frames(kura: &Kura, height: usize) -> Vec<Vec<u8>> {
    (1..=height)
        .map(|height| {
            kura.canonical_block_wire_bytes_for_testing(
                NonZeroUsize::new(height).expect("non-zero"),
            )
            .expect("persisted canonical frame")
        })
        .collect()
}

/// Every persisted frame is the canonical first-release wire of the block it decodes to.
fn assert_canonical_frames(frames: &[Vec<u8>]) {
    for (index, frame) in frames.iter().enumerate() {
        let block = decode_framed_signed_block(frame).expect("the persisted frame decodes");
        assert_eq!(block.header().height().get(), index as u64 + 1);
        assert_eq!(
            block.encode_wire().expect("canonical frame"),
            *frame,
            "the persisted bytes of block {} are its canonical frame",
            index + 1
        );
    }
}

/// Rebuild a State from `disk` alone through the production startup path: an empty State, the
/// `supplied` genesis (a restart supplies none) and no snapshot.
fn cold_replay(
    identity: &Chain,
    disk: &Disk,
    supplied: Option<SignedBlock>,
) -> (Arc<State>, Result<Prepared, NodeError>) {
    let state = empty_state(&identity.chain_id, &identity.genesis, &disk.kura);
    let prepared = prepare(PrepareInputs {
        state: Arc::clone(&state),
        events: tokio::sync::broadcast::channel(64).0,
        genesis: supplied,
        genesis_account: SAMPLE_GENESIS_ACCOUNT_ID.clone(),
        consensus_mode: ConsensusMode::Permissioned,
    });
    (state, prepared)
}

/// Drop a prepared instance and its State once the detached executor thread released it, so the
/// next startup over the same store is the only owner again.
fn release(state: Arc<State>, prepared: Prepared) {
    drop(prepared);
    await_sole_owner(
        &state,
        "the State of a dropped prepared instance (its executor thread)",
    );
}

/// Commit `count` blocks of real work on a running four-validator chain.
fn commit_work(chain: &Chain, validators: &[Validator], label: &str, count: usize) {
    for index in 0..count {
        let hash = submit(chain, validators, &format!("{label} {index}"));
        wait_until(
            validators,
            Duration::from_secs(30),
            "history committed",
            || committed_everywhere(validators, hash),
        );
    }
}

/// Each running validator's stored complete World root (Appendix E, E51), as text.
fn stored_roots(validators: &[Validator]) -> Vec<Result<String, String>> {
    world_state_roots(validators)
        .into_iter()
        .map(|root| root.map(|root| root.to_string()))
        .collect()
}

/// The complete World root of a rebuilt State, checked against a cold capture, as text.
fn world_root(state: &State) -> Result<String, String> {
    state
        .verify_world_state_accumulator()
        .map(|root| root.to_string())
        .map_err(|error| error.to_string())
}

/// Cold restart and full replay (`specs/sumeragi.md` §12.1) from the persisted bytes: every
/// validator's store is closed, reopened from its directory and replayed with no supplied
/// genesis and no snapshot. Each rebuilds the State it had before shutdown, and neither the
/// reopen nor the replay rewrites a persisted frame.
#[test]
fn current_genesis_history_replays_from_reopened_stores_to_the_identical_state() {
    let chain = chain(4, 200);
    let disks = stored_disks(&chain);
    let validators = start_all(&chain, &disks, true);
    commit_work(&chain, &validators, "history", 3);
    assert_eq!(committed_heights(&validators), vec![4; 4]);
    let roots = stored_roots(&validators);
    assert!(
        roots[0].is_ok() && roots.iter().all(|root| *root == roots[0]),
        "every validator certified the same complete World: {roots:?}"
    );
    let tips = validators
        .iter()
        .map(|validator| validator.state.view().native_execution_tip())
        .collect::<Vec<_>>();
    assert!(tips[0].is_some() && tips.iter().all(|tip| *tip == tips[0]));
    shutdown(validators);
    let height = 4_usize;
    assert_same_certified_blocks(&disks, height);
    let frames = disks
        .iter()
        .map(|disk| persisted_frames(&disk.kura, height))
        .collect::<Vec<_>>();
    for frames in &frames {
        assert_canonical_frames(frames);
    }

    // Nothing of the running validators survives: only their directories.
    let disks = disks.into_iter().map(reopen).collect::<Vec<_>>();
    for (index, disk) in disks.iter().enumerate() {
        assert_eq!(disk.kura.blocks_count(), height);
        assert_eq!(
            persisted_frames(&disk.kura, height),
            frames[index],
            "reopening validator {index}'s store rewrites nothing"
        );
        let (state, prepared) = cold_replay(&chain, disk, None);
        let prepared =
            prepared.expect("the persisted current-genesis history replays without other inputs");
        assert_eq!(startup::applied_height(&state), height as u64);
        assert_eq!(
            world_root(&state),
            roots[index],
            "replay reproduces the complete World root validator {index} had before shutdown"
        );
        assert_eq!(state.view().native_execution_tip(), tips[index]);
        assert_eq!(
            prepared.instance(),
            root_instance(&chain.genesis, &chain.chain_id.to_string()).unwrap(),
            "the replayed instance is the one the stored genesis defines"
        );
        release(state, prepared);
        assert_eq!(
            persisted_frames(&disk.kura, height),
            frames[index],
            "replay never rewrites the persisted history of validator {index}"
        );
    }

    // The replayed stores are still the live history: the cluster restarts on them, reaches the
    // same World and extends the same chain.
    let validators = start_all(&chain, &disks, false);
    assert_eq!(stored_roots(&validators), roots);
    commit_work(&chain, &validators, "after cold replay", 1);
    assert_eq!(committed_heights(&validators), vec![5; 4]);
    shutdown(validators);
    assert_same_certified_blocks(&disks, 5);
    for (index, disk) in disks.iter().enumerate() {
        assert_eq!(
            persisted_frames(&disk.kura, height),
            frames[index],
            "extending the chain appends; it rewrites no earlier frame"
        );
    }
}

/// A deliberately incompatible first-release change is a new genesis, hence a new history. A
/// node configured for the new genesis is refused on the old store by the store's durable
/// network binding, before a State exists and again when the empty State is anchored; a supplied
/// foreign genesis is refused by startup. Nothing migrates, re-roots or partially replays the
/// old blocks, the old store stays replayable under its own genesis, and the new genesis starts
/// on a fresh store.
///
/// The daemon anchors the empty State (`prepare_configured_primary_geometry_anchor`) before it
/// calls `prepare`, so a State of another network never reaches replay.
#[test]
fn a_store_never_replays_under_another_genesis() {
    let old = chain(4, 200);
    // Any signed difference is another genesis; here one consensus parameter.
    let new = chain(4, 300);
    assert_ne!(old.genesis.hash(), new.genesis.hash());
    let old_instance = root_instance(&old.genesis, &old.chain_id.to_string()).unwrap();
    let new_instance = root_instance(&new.genesis, &new.chain_id.to_string()).unwrap();
    assert_ne!(
        old_instance, new_instance,
        "the instance peers bind in the handshake separates the two histories"
    );
    let new_network = NetworkId::from_genesis_hash(new.genesis.hash());
    let catalog = iroha_data_model::nexus::LaneCatalog::default();

    let mut disks = stored_disks(&old);
    let validators = start_all(&old, &disks, true);
    commit_work(&old, &validators, "old history", 1);
    let root = stored_roots(&validators).swap_remove(0);
    assert!(root.is_ok(), "{root:?}");
    shutdown(validators);
    // The restarted node: a store handle opened from disk, bound to no network in memory.
    let disk = reopen(disks.swap_remove(0));
    drop(disks);
    let frames = persisted_frames(&disk.kura, 2);

    // The daemon's empty-state preflight, before any State exists.
    let preflight =
        State::preflight_configured_primary_geometry_replay(&disk.kura, &new_network, &catalog)
            .expect_err("a store of another network must fail the replay preflight")
            .to_string();
    assert!(preflight.contains(FOREIGN_STORE), "{preflight}");

    // A node configured for the new genesis and restarted with no supplied genesis: its empty
    // State cannot be anchored to the old store.
    let mut foreign = State::try_new_with_chain_and_network_id_with_default_telemetry(
        crate::state::AllocationBudget::new(defaults::pipeline::IVM_EXECUTION_MAX_BYTES),
        initial_world(),
        Arc::clone(&disk.kura),
        LiveQueryStore::start_test(),
        new.chain_id.clone(),
        new_network,
    )
    .expect("constructing an empty State opens no lane storage");
    let anchor = foreign
        .prepare_configured_primary_geometry_anchor(&catalog)
        .expect_err("a State of another network must not anchor to this store")
        .to_string();
    assert!(anchor.contains(FOREIGN_STORE), "{anchor}");
    assert_eq!(foreign.committed_height(), 0);
    drop(foreign);

    // Startup itself: the supplied genesis must be the one the store holds.
    let (state, refused) = cold_replay(&old, &disk, Some(new.genesis.clone()));
    match refused {
        Err(NodeError::Input(reason)) => assert!(
            reason.contains("differs from the one Kura holds"),
            "{reason}"
        ),
        other => panic!("a foreign genesis must be refused before genesis executes: {other:?}"),
    }
    assert_eq!(
        startup::applied_height(&state),
        0,
        "nothing of either history was applied"
    );
    drop(state);
    assert_eq!(disk.kura.blocks_count(), 2);
    assert_eq!(persisted_frames(&disk.kura, 2), frames);

    // The refusals changed nothing: the old history still replays from its store alone.
    let (state, replayed) = cold_replay(&old, &disk, None);
    let replayed = replayed.expect("the old history replays under its own genesis");
    assert_eq!(replayed.instance(), old_instance);
    assert_eq!(world_root(&state), root);
    release(state, replayed);
    assert_eq!(persisted_frames(&disk.kura, 2), frames);

    // The cutover: the new genesis starts its own history on a fresh store.
    let fresh = stored_disk();
    let (state, started) = cold_replay(&new, &fresh, Some(new.genesis.clone()));
    let started = started.expect("a fresh genesis starts on a fresh store");
    assert_eq!(started.instance(), new_instance);
    assert_eq!(startup::applied_height(&state), GENESIS_HEIGHT);
    assert_eq!(fresh.kura.blocks_count(), 1);
    assert_eq!(
        decode_framed_signed_block(&persisted_frames(&fresh.kura, 1)[0])
            .expect("the persisted new genesis")
            .hash(),
        new.genesis.hash()
    );
    assert_eq!(disk.kura.blocks_count(), 2, "the old store is untouched");
}

/// The stored block wire has one layout: version byte 1, the Norito header with the fixed V1
/// flags, and the canonical payload. Every other version, a headerless payload and another
/// header layout are refused by the decoder storage and distribution use.
#[test]
fn stored_block_wire_is_exactly_the_framed_first_release_layout() {
    let chain = chain(4, 200);
    let frame = chain
        .genesis
        .encode_wire()
        .expect("canonical genesis frame");
    assert_eq!(
        SignedBlock::WIRE_VERSION,
        1,
        "exactly one block wire version"
    );
    assert_eq!(frame[0], 1);
    let decoded = decode_framed_signed_block(&frame).expect("the current wire decodes");
    assert_eq!(decoded.hash(), chain.genesis.hash());
    assert_eq!(decoded.encode_wire().expect("re-encode"), frame);

    for version in [0_u8, 2, 3, u8::MAX] {
        let mut other = frame.clone();
        other[0] = version;
        assert!(
            decode_framed_signed_block(&other).is_err(),
            "block wire version {version} has no decoder"
        );
    }
    let mut bare = vec![frame[0]];
    bare.extend_from_slice(&frame[1 + norito::core::Header::SIZE..]);
    assert!(
        decode_framed_signed_block(&bare).is_err(),
        "a headerless payload is not a stored block"
    );
    let header = norito::core::Header::SIZE;
    // Norito major and minor version, then the layout flags closing the header.
    for (offset, what) in [(1 + 4, "major"), (1 + 5, "minor"), (header, "flags")] {
        let mut other = frame.clone();
        other[offset] ^= 0x01;
        assert!(
            decode_framed_signed_block(&other).is_err(),
            "another Norito {what} is not the first-release layout"
        );
    }
    let mut trailing = frame.clone();
    trailing.push(0);
    assert!(decode_framed_signed_block(&trailing).is_err());
}

/// A text field of a JSON fixture.
fn text(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("fixture text field `{key}`"))
        .to_owned()
}

/// A pinned history: its identity, frames and the State they replay to.
struct PinnedHistory {
    chain_id: ChainId,
    frames: Vec<Vec<u8>>,
    block_hashes: Vec<String>,
    world_state_root: String,
    execution_tip: Value,
}

/// Load the pinned history under `dir`, checking every frame against the digest its manifest
/// records.
fn load_pinned_history(dir: &Path) -> PinnedHistory {
    let manifest = std::fs::read(dir.join("manifest.json"))
        .unwrap_or_else(|error| panic!("{}/manifest.json: {error}", dir.display()));
    let manifest: Value = norito::json::from_slice(&manifest).expect("pinned history manifest");
    assert_eq!(text(&manifest, "format"), PINNED_FORMAT);
    let blocks = manifest
        .get("blocks")
        .and_then(Value::as_array)
        .expect("pinned blocks");
    assert!(blocks.len() >= 2, "a pinned genesis and certified blocks");
    let mut frames = Vec::new();
    let mut block_hashes = Vec::new();
    let mut history = Sha256::new();
    for (index, block) in blocks.iter().enumerate() {
        assert_eq!(
            block.get("height").and_then(Value::as_u64),
            Some(index as u64 + 1)
        );
        let file = text(block, "file");
        let frame = std::fs::read(dir.join(&file))
            .unwrap_or_else(|error| panic!("{}/{file}: {error}", dir.display()));
        assert_eq!(
            hex::encode(Sha256::digest(&frame)),
            text(block, "sha256"),
            "pinned frame {file} differs from its recorded digest"
        );
        history.update(&frame);
        block_hashes.push(text(block, "block_hash"));
        frames.push(frame);
    }
    assert_eq!(
        hex::encode(history.finalize()),
        text(&manifest, "history_sha256")
    );
    PinnedHistory {
        chain_id: text(&manifest, "chain_id")
            .parse()
            .expect("pinned chain id"),
        frames,
        block_hashes,
        world_state_root: text(&manifest, "world_state_root"),
        execution_tip: manifest
            .get("execution_tip")
            .cloned()
            .expect("pinned execution tip"),
    }
}

/// Flip the last byte of `frame` where the store under `root` persisted it.
fn corrupt_persisted_frame(root: &Path, frame: &[u8]) {
    let data = Kura::canonical_storage_path(root).join("blocks.data");
    let mut bytes = std::fs::read(&data).expect("block data file");
    let offset = bytes
        .windows(frame.len())
        .position(|window| window == frame)
        .expect("the store persists the canonical frame verbatim");
    bytes[offset + frame.len() - 1] ^= 0x01;
    std::fs::write(&data, bytes).expect("rewrite block data file");
}

/// Replay across builds: frames a previous build wrote are stored through the production
/// persistence path, read back from disk and replayed with no supplied genesis. This build must
/// reach the pinned block hashes, World root and execution tip. A change that alters the bytes,
/// validity or certified result of anything in the pinned history fails here; it is then a
/// deliberately incompatible change and must declare its cutover and regenerate the fixture.
///
/// The last step shows startup reads the persisted bytes: with one byte of a stored frame
/// flipped, Strict startup refuses the store while decoding it.
#[test]
fn pinned_history_of_an_earlier_build_replays_to_its_pinned_state() {
    // Only for the node fixture runtime (logger, instruction registry): the history replayed
    // below is the pinned one, not this fresh genesis.
    let _runtime = chain(4, 200);
    let pinned = load_pinned_history(&repository_path(PINNED_HISTORY));
    let height = pinned.frames.len();
    let blocks = pinned
        .frames
        .iter()
        .map(|frame| decode_framed_signed_block(frame).expect(PINNED_REPLAY_RULE))
        .collect::<Vec<_>>();
    assert_eq!(
        blocks
            .iter()
            .map(|block| block.hash().to_string())
            .collect::<Vec<_>>(),
        pinned.block_hashes,
        "{PINNED_REPLAY_RULE}"
    );
    let identity = Chain {
        genesis: blocks[0].clone(),
        keys: Vec::new(),
        chain_id: pinned.chain_id.clone(),
    };

    // Store the pinned frames through Kura's production persistence path.
    let disk = stored_disk();
    let budget = iroha_allocation::AllocationBudget::new(64 * 1024 * 1024);
    let state = empty_state(&identity.chain_id, &identity.genesis, &disk.kura);
    for block in blocks {
        disk.kura
            .store_block(SharedSignedBlock::try_new(block, &budget).expect("admit pinned block"))
            .expect(PINNED_REPLAY_RULE);
    }
    assert_eq!(
        persisted_frames(&disk.kura, height),
        pinned.frames,
        "Kura persists the pinned frames byte for byte"
    );
    await_sole_owner(&state, "the State that bound the store");
    drop(state);

    // A restart: the store is read back from disk and replayed with nothing else supplied.
    let disk = reopen(disk);
    assert_eq!(disk.kura.blocks_count(), height);
    let (state, prepared) = cold_replay(&identity, &disk, None);
    let prepared = prepared.unwrap_or_else(|error| panic!("{PINNED_REPLAY_RULE}: {error}"));
    assert_eq!(startup::applied_height(&state), height as u64);
    {
        // Read the original policy restored from the pinned signed genesis.
        let view = state.view();
        let parameters = view.world().parameters();
        assert_eq!(
            parameters.sumeragi().max_block_bytes.get(),
            16 * 1024 * 1024
        );
        assert_eq!(
            parameters.transaction().max_tx_bytes().get(),
            10 * 1024 * 1024
        );
    }
    assert_eq!(
        world_root(&state),
        Ok(pinned.world_state_root.clone()),
        "{PINNED_REPLAY_RULE}"
    );
    let tip = state
        .view()
        .native_execution_tip()
        .expect("replayed execution tip");
    assert_eq!(
        norito::json::to_value(&tip).expect("execution tip"),
        pinned.execution_tip,
        "{PINNED_REPLAY_RULE}"
    );
    release(state, prepared);
    assert_eq!(
        persisted_frames(&disk.kura, height),
        pinned.frames,
        "replay never rewrites the pinned history"
    );

    // Replay depends on the persisted bytes: alter one and the store does not start.
    let Disk { kura, dir } = disk;
    await_sole_owner(&kura, "the replayed Kura store");
    drop(kura);
    let root = store_root(&dir);
    corrupt_persisted_frame(&root, &pinned.frames[1]);
    let refusal = match try_open_store(&root) {
        Err(refusal) => refusal,
        Ok(_) => panic!("Strict startup must refuse a store whose persisted frame was altered"),
    };
    assert!(
        refusal.contains("CodecAttempt") || refusal.contains("CanonicalBlockWireMismatch"),
        "the altered frame itself is what stops startup: {refusal}"
    );
}

/// Write a pinned history under `dir`: one `block-<height>.wire` per frame and `manifest.json`.
/// Returns the SHA-256 of the frames in order, which the inventory records.
fn write_pinned_history(
    dir: &Path,
    chain: &Chain,
    frames: &[Vec<u8>],
    world_state_root: &str,
    execution_tip: &Value,
) -> String {
    std::fs::create_dir_all(dir).expect("pinned history directory");
    for entry in std::fs::read_dir(dir).expect("pinned history directory") {
        let path = entry.expect("pinned history entry").path();
        if path
            .extension()
            .is_some_and(|extension| extension == "wire")
        {
            std::fs::remove_file(&path).expect("remove the previous pinned frame");
        }
    }
    let number = |value: u64| norito::json::to_value(&value).expect("number");
    let mut history = Sha256::new();
    let mut blocks = Vec::new();
    for (index, frame) in frames.iter().enumerate() {
        let file = format!("block-{}.wire", index + 1);
        std::fs::write(dir.join(&file), frame).expect("write pinned frame");
        history.update(frame);
        let block = decode_framed_signed_block(frame).expect("persisted frame");
        let mut entry = norito::json::Map::new();
        entry.insert("height".into(), number(index as u64 + 1));
        entry.insert("file".into(), Value::String(file));
        entry.insert("bytes".into(), number(frame.len() as u64));
        entry.insert(
            "sha256".into(),
            Value::String(hex::encode(Sha256::digest(frame))),
        );
        entry.insert("block_hash".into(), Value::String(block.hash().to_string()));
        blocks.push(Value::Object(entry));
    }
    let history = hex::encode(history.finalize());
    let mut generator = norito::json::Map::new();
    generator.insert(
        "path".into(),
        Value::String("crates/iroha_core/src/sumeragi/node/tests/history_cutover_tests.rs".into()),
    );
    generator.insert(
        "test".into(),
        Value::String(
            "sumeragi::node::tests::history_cutover_tests::capture_pinned_first_release_history"
                .into(),
        ),
    );
    let mut manifest = norito::json::Map::new();
    manifest.insert("format".into(), Value::String(PINNED_FORMAT.into()));
    manifest.insert("chain_id".into(), Value::String(chain.chain_id.to_string()));
    manifest.insert("validators".into(), number(chain.keys.len() as u64));
    manifest.insert("blocks".into(), Value::Array(blocks));
    manifest.insert("history_sha256".into(), Value::String(history.clone()));
    manifest.insert(
        "world_state_root".into(),
        Value::String(world_state_root.to_owned()),
    );
    manifest.insert("execution_tip".into(), execution_tip.clone());
    manifest.insert("generator".into(), Value::Object(generator));
    let mut rendered =
        norito::json::to_json_pretty(&Value::Object(manifest)).expect("pinned manifest");
    rendered.push('\n');
    std::fs::write(dir.join("manifest.json"), rendered).expect("write pinned manifest");
    history
}

/// Explicit exporter of the pinned history. Four validators commit two blocks of work on the
/// node fixture genesis; validator 0's persisted frames, the block hashes, the complete World
/// root and the execution tip are written to the directory that
/// `IROHA_CAPTURE_FIRST_RELEASE_HISTORY_DIR` names (an absolute path), and read back.
///
/// Without that variable the capture goes to a scratch directory, so running every ignored test
/// never rewrites `fixtures/core/first_release_history`. Point it at the fixture only for a
/// deliberately incompatible change, with its declared cutover
/// (`specs/first_release_history_cutover.md`). Block times are the wall clock, so every capture
/// is a new history.
#[test]
#[ignore = "explicit capture of the pinned first-release history, not a qualification gate"]
fn capture_pinned_first_release_history() {
    let chain = chain(4, 200);
    let disks = stored_disks(&chain);
    let validators = start_all(&chain, &disks, true);
    // Read the policies actually installed by the original signed genesis.
    // The former 4 MiB block cap cannot contain the canonical 10 MiB transaction
    // cap plus its block reserve; a new history uses the coherent current pair.
    for validator in &validators {
        let view = validator.state.view();
        let parameters = view.world().parameters();
        assert_eq!(
            parameters.sumeragi().max_block_bytes.get(),
            16 * 1024 * 1024
        );
        assert_eq!(
            parameters.transaction().max_tx_bytes().get(),
            10 * 1024 * 1024
        );
    }
    println!("PINNED_FIRST_RELEASE_HISTORY_POLICY=max_block_bytes:16777216,max_tx_bytes:10485760");
    commit_work(&chain, &validators, "pinned history", 2);
    let height = 3_usize;
    assert_eq!(committed_heights(&validators), vec![height as u64; 4]);
    let root = stored_roots(&validators)
        .swap_remove(0)
        .expect("certified complete World root");
    let tip = validators[0]
        .state
        .view()
        .native_execution_tip()
        .expect("execution tip");
    let tip = norito::json::to_value(&tip).expect("execution tip");
    shutdown(validators);
    assert_same_certified_blocks(&disks, height);
    let frames = persisted_frames(&disks[0].kura, height);
    assert_canonical_frames(&frames);

    let scratch = tempfile::tempdir().expect("tempdir");
    let dir = std::env::var_os(CAPTURE_DIR).map_or_else(
        || scratch.path().join("first_release_history"),
        PathBuf::from,
    );
    assert!(
        dir.is_absolute(),
        "{CAPTURE_DIR} must be an absolute path: {}",
        dir.display()
    );
    let history = write_pinned_history(&dir, &chain, &frames, &root, &tip);
    let written = load_pinned_history(&dir);
    assert_eq!(written.chain_id, chain.chain_id);
    assert_eq!(written.frames, frames);
    assert_eq!(written.block_hashes.len(), height);
    assert_eq!(written.world_state_root, root);
    assert_eq!(written.execution_tip, tip);
    println!("PINNED_FIRST_RELEASE_HISTORY_DIR={}", dir.display());
    println!("PINNED_FIRST_RELEASE_HISTORY_SHA256={history}");
}

/// Every retired store artifact of the inventory (`retired_store_artifacts`) still stops Strict
/// startup: planted in a store that a genesis network is anchored to, each is refused with its
/// listed error and left in place, and the store opens again once the operator removes it. The
/// inventory is therefore what the node refuses, whatever the refusal's source looks like.
///
/// A store no network was anchored to yet admits only its empty canonical files, so there the
/// same artifacts are refused earlier, as unexpected entries.
#[test]
fn every_inventoried_retired_store_artifact_stops_strict_startup() {
    let chain = chain(4, 200);
    let inventory = std::fs::read(repository_path(INVENTORY)).expect("history inventory");
    let inventory: Value = norito::json::from_slice(&inventory).expect("history inventory JSON");
    let refusals = inventory
        .get("retired_store_artifacts")
        .and_then(Value::as_array)
        .expect("retired_store_artifacts");
    let mut refused = 0_usize;
    for refusal in refusals {
        let location = text(refusal, "location");
        let expected = text(refusal, "error");
        let artifacts = refusal
            .get("artifacts")
            .and_then(Value::as_array)
            .expect("artifacts");
        // One store per refusal, anchored to the chain's network as a store with history is.
        let dir = tempfile::tempdir().expect("tempdir");
        let root = store_root(&dir);
        let kura = open_store(&root);
        drop(empty_state(&chain.chain_id, &chain.genesis, &kura));
        await_sole_owner(&kura, "the anchored Kura store");
        drop(kura);
        for artifact in artifacts {
            let name = text(artifact, "name");
            let base = match location.as_str() {
                "store_root" => root.clone(),
                "blocks_root" => Kura::canonical_storage_path(&root),
                other => panic!("unknown retired artifact location `{other}`"),
            };
            let path = base.join(text(artifact, "plant"));
            let parent = path.parent().expect("artifact parent").to_path_buf();
            let created_parent = !parent.exists();
            std::fs::create_dir_all(&parent).expect("artifact parent");
            match text(artifact, "kind").as_str() {
                "file" => std::fs::write(&path, b"retired artifact").expect("plant file"),
                "directory" => std::fs::create_dir(&path).expect("plant directory"),
                other => panic!("unknown retired artifact kind `{other}`"),
            }
            let error = match try_open_store(&root) {
                Err(error) => error,
                Ok(_) => panic!("retired store artifact `{name}` no longer stops Strict startup"),
            };
            assert!(
                error.contains(&expected),
                "`{name}` must be refused as `{expected}`: {error}"
            );
            assert!(
                std::fs::symlink_metadata(&path).is_ok(),
                "`{name}` stays for the operator to remove"
            );
            if path.is_dir() {
                std::fs::remove_dir(&path).expect("remove planted directory");
            } else {
                std::fs::remove_file(&path).expect("remove planted file");
            }
            if created_parent {
                std::fs::remove_dir(&parent).expect("remove planted parent");
            }
            drop(open_store(&root));
            refused += 1;
        }
    }
    assert!(
        refused >= 28,
        "the inventory lists every retired store artifact: {refused}"
    );
}
