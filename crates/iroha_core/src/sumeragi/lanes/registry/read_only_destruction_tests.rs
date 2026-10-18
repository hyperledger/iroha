//! Real signed-frame read owners release their mutex before final authority callbacks.

use super::*;

struct ReadDropProbe {
    armed: AtomicBool,
    calls: AtomicUsize,
    locks_free: AtomicBool,
    reentered: AtomicUsize,
}

struct ReadDropSchedule {
    original: Arc<dyn AvailabilitySchedule>,
    source: std::sync::Weak<LaneFrameSource>,
    probe: Arc<ReadDropProbe>,
}

impl AvailabilitySchedule for ReadDropSchedule {
    fn instance(&self) -> Hash32 {
        self.original.instance()
    }
    fn height_config(&self, height: u64) -> Result<Option<HeightConfig>, Attempt<io::Error>> {
        self.original.height_config(height)
    }
}

impl Drop for ReadDropSchedule {
    fn drop(&mut self) {
        if !self.probe.armed.load(Ordering::SeqCst) {
            return;
        }
        let Some(source) = self.source.upgrade() else {
            return;
        };
        self.probe.calls.fetch_add(1, Ordering::SeqCst);
        let free = source.read_lock_available_for_test();
        self.probe.locks_free.fetch_and(free, Ordering::SeqCst);
        // A final authority callback may re-enter the owner. Its original in-flight
        // selection must remain exclusive, without holding a mutex across Drop.
        if free
            && matches!(source.wait_for(LANE, &INCARNATION, 1, Duration::ZERO),
            Err(error) if error.io_kind() == io::ErrorKind::WouldBlock)
        {
            self.probe.reentered.fetch_add(1, Ordering::SeqCst);
        }
    }
}

struct ReadDropAuthorities {
    original: Arc<dyn LaneStoreAuthorities>,
    source: std::sync::Weak<LaneFrameSource>,
    probe: Arc<ReadDropProbe>,
}

impl LaneStoreAuthorities for ReadDropAuthorities {
    fn authority(
        &self,
        lane: LaneId,
        incarnation: &[u8; 32],
        instance: Hash32,
    ) -> Result<Option<LaneStoreAuthority>, Attempt<io::Error>> {
        self.original
            .authority(lane, incarnation, instance)
            .map(|selected| {
                selected.map(|selected| LaneStoreAuthority {
                    schedule: Arc::new(ReadDropSchedule {
                        original: selected.schedule,
                        source: self.source.clone(),
                        probe: Arc::clone(&self.probe),
                    }),
                })
            })
    }
}

fn read_only_final_authority_control(prepare_first: bool, missing: bool) {
    let fixture = Fixture::new(true);
    fixture.publish();
    let bytes = fs::read(fixture.path()).unwrap();
    let budget = fixture.stores.budget.clone();
    let baseline = budget.reserved_bytes();
    let ceiling = budget.limit_bytes();
    let probe = Arc::new(ReadDropProbe {
        armed: AtomicBool::new(true),
        calls: AtomicUsize::new(0),
        locks_free: AtomicBool::new(true),
        reentered: AtomicUsize::new(0),
    });
    let reader = Arc::new_cyclic(|weak| {
        LaneFrameSource::new(
            fixture.dir.path().to_path_buf(),
            fixture.stores.network,
            fixture.stores.chain_id.clone(),
            Arc::clone(&fixture.stores.crypto),
            budget.clone(),
            Arc::new(ReadDropAuthorities {
                original: fixture.authorities.clone(),
                source: weak.clone(),
                probe: Arc::clone(&probe),
            }),
        )
    });
    if prepare_first {
        assert!(
            reader
                .wait_for(LANE, &INCARNATION, 1, Duration::ZERO)
                .unwrap()
        );
        assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
    }
    let result = reader.block(LANE, &INCARNATION, if missing { 2 } else { 1 });
    probe.armed.store(false, Ordering::SeqCst);
    if missing {
        assert!(matches!(result, Err(error) if error.io_kind() == io::ErrorKind::NotFound));
    } else {
        let block = result.unwrap().unwrap();
        assert_eq!(block.block_hash, fixture.qc.block_hash);
        assert_eq!(block.result, fixture.qc.result);
        assert!(block.batch.is_some());
    }
    let expected = if prepare_first && missing { 2 } else { 1 };
    assert_eq!(probe.calls.load(Ordering::SeqCst), expected);
    assert_eq!(budget.reserved_bytes(), baseline);
    assert_eq!(budget.limit_bytes(), ceiling);
    assert_eq!(fs::read(fixture.path()).unwrap(), bytes);
    assert!(
        probe.locks_free.load(Ordering::SeqCst),
        "final original read-only authority destructor must run after read mutex unlock"
    );
    assert_eq!(
        probe.reentered.load(Ordering::SeqCst),
        expected,
        "read-only final authority reentry must preserve the original in-flight selection"
    );
    let block = reader.block(LANE, &INCARNATION, 1).unwrap().unwrap();
    assert_eq!(block.block_hash, fixture.qc.block_hash);
    assert_eq!(block.result, fixture.qc.result);
    assert!(block.batch.is_some());
    drop(block);
    assert_eq!(budget.reserved_bytes(), baseline);
    assert_eq!(fs::read(fixture.path()).unwrap(), bytes);
}

#[test]
fn completed_read_only_frame_destroys_final_authority_after_read_unlock() {
    read_only_final_authority_control(true, false);
}

#[test]
fn missing_read_only_frame_destroys_final_authority_after_read_unlock() {
    read_only_final_authority_control(false, true);
}

#[test]
fn reselected_read_only_frame_destroys_each_final_authority_after_read_unlock() {
    read_only_final_authority_control(true, true);
}

#[test]
fn read_only_capacity_retry_retains_the_original_authority_and_partial_frame() {
    let fixture = Fixture::new(true);
    fixture.publish();
    let bytes = fs::read(fixture.path()).unwrap();
    let budget = fixture.stores.budget.clone();
    let baseline = budget.reserved_bytes();
    let ceiling = budget.limit_bytes();
    let reader = LaneFrameSource::new(
        fixture.dir.path().to_path_buf(),
        fixture.stores.network,
        fixture.stores.chain_id.clone(),
        Arc::clone(&fixture.stores.crypto),
        budget.clone(),
        fixture.authorities.clone(),
    );
    let calls = fixture.authorities.calls.load(Ordering::SeqCst);
    budget.set_limit_bytes(baseline + bytes.len());
    let refusal = reader.block(LANE, &INCARNATION, 1);
    let retained = budget.reserved_bytes();
    budget.set_limit_bytes(ceiling);
    assert!(
        matches!(refusal, Err(Attempt::Deferred(_))),
        "actual frame decoding must retain its original capacity refusal"
    );
    assert_eq!(retained, baseline + bytes.len());
    assert_eq!(fixture.authorities.calls.load(Ordering::SeqCst), calls + 1);
    let block = reader.block(LANE, &INCARNATION, 1).unwrap().unwrap();
    assert_eq!(block.block_hash, fixture.qc.block_hash);
    assert_eq!(block.result, fixture.qc.result);
    assert!(block.batch.is_some());
    drop(block);
    assert_eq!(
        fixture.authorities.calls.load(Ordering::SeqCst),
        calls + 1,
        "read retry must keep the original schedule and partial frame owner"
    );
    assert_eq!(budget.reserved_bytes(), baseline);
    assert_eq!(budget.limit_bytes(), ceiling);
    assert_eq!(fs::read(fixture.path()).unwrap(), bytes);
}

struct PostOpenMissingSchedule {
    original: Arc<dyn AvailabilitySchedule>,
    path: PathBuf,
    moved: PathBuf,
    first: Arc<AtomicBool>,
}
impl AvailabilitySchedule for PostOpenMissingSchedule {
    fn instance(&self) -> Hash32 {
        self.original.instance()
    }
    fn height_config(&self, height: u64) -> Result<Option<HeightConfig>, Attempt<io::Error>> {
        if self.first.swap(false, Ordering::SeqCst) {
            // RestoreFrame reaches this independent authority only after it opened
            // and decoded the actual funded canonical frame. Produce real native
            // NotFound now; the opened original must not be treated as initial absence.
            fs::rename(&self.path, &self.moved)?;
            return Err(fs::metadata(&self.path)
                .expect_err("the original frame was moved before native lookup")
                .into());
        }
        self.original.height_config(height)
    }
}
struct PostOpenMissingAuthorities {
    original: Arc<dyn LaneStoreAuthorities>,
    path: PathBuf,
    moved: PathBuf,
    first: Arc<AtomicBool>,
}
impl LaneStoreAuthorities for PostOpenMissingAuthorities {
    fn authority(
        &self,
        lane: LaneId,
        incarnation: &[u8; 32],
        instance: Hash32,
    ) -> Result<Option<LaneStoreAuthority>, Attempt<io::Error>> {
        self.original
            .authority(lane, incarnation, instance)
            .map(|authority| {
                authority.map(|authority| LaneStoreAuthority {
                    schedule: Arc::new(PostOpenMissingSchedule {
                        original: authority.schedule,
                        path: self.path.clone(),
                        moved: self.moved.clone(),
                        first: Arc::clone(&self.first),
                    }),
                })
            })
    }
}

#[test]
fn read_only_post_open_not_found_retains_original_source() {
    let fixture = Fixture::new(true);
    fixture.publish();
    let path = fixture.path();
    let moved = fixture.dir.path().join("retained-original-frame");
    let bytes = fs::read(&path).unwrap();
    let budget = fixture.stores.budget.clone();
    let baseline = budget.reserved_bytes();
    let ceiling = budget.limit_bytes();
    let calls = fixture.authorities.calls.load(Ordering::SeqCst);
    let reader = LaneFrameSource::new(
        fixture.dir.path().to_path_buf(),
        fixture.stores.network,
        fixture.stores.chain_id.clone(),
        fixture.stores.crypto.clone(),
        budget.clone(),
        Arc::new(PostOpenMissingAuthorities {
            original: fixture.authorities.clone(),
            path: path.clone(),
            moved: moved.clone(),
            first: Arc::new(AtomicBool::new(true)),
        }),
    );
    let refused = reader.block(LANE, &INCARNATION, 1);
    let original_native = matches!(&refused,
        Err(Attempt::Rejected(error)) if error.kind() == io::ErrorKind::NotFound && error.raw_os_error().is_some());
    let funded_original = budget.reserved_bytes() > baseline;
    let moved_original = moved.is_file() && !path.exists();
    // The same bytes at a new inode are deliberately insufficient to replace the
    // admitted source. A correct retry does not request another schedule or open.
    fs::write(&path, &bytes).unwrap();
    let completed = reader.block(LANE, &INCARNATION, 1);
    let exact_result = matches!(&completed, Ok(Some(block))
        if block.block_hash == fixture.qc.block_hash && block.result == fixture.qc.result && block.batch.is_some());
    let same_authority = fixture.authorities.calls.load(Ordering::SeqCst) == calls + 1;
    drop(completed);
    drop(refused);
    drop(reader);
    fs::remove_file(&path).unwrap();
    fs::rename(&moved, &path).unwrap();
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert_eq!(budget.reserved_bytes(), baseline);
    assert_eq!(budget.limit_bytes(), ceiling);
    assert!(
        original_native && moved_original,
        "the original opened frame must reach actual native NotFound"
    );
    assert!(
        funded_original && same_authority && exact_result,
        "post-open NotFound must retain the original funded frame and authority without recapture"
    );
}
