//! Original sample backing survives actual World rollback and publication.
use iroha_allocation::AllocationBudget;
use iroha_data_model::sumeragi_lanes::{
    SumeragiLaneSample, SumeragiLaneSamples, SumeragiLaneState,
};
fn sample(height: u64) -> SumeragiLaneSample {
    SumeragiLaneSample {
        height,
        time_ms: height * 1000,
        transactions: height,
        lanes: 1,
    }
}
fn demand(count: usize) -> usize {
    count * std::mem::size_of::<SumeragiLaneSample>() + SumeragiLaneSamples::control_layout().size()
}
fn state(pool: &AllocationBudget) -> SumeragiLaneState {
    SumeragiLaneState {
        samples: SumeragiLaneSamples::try_from(vec![sample(1), sample(2), sample(3)])
            .unwrap()
            .admit(pool)
            .unwrap(),
        ..SumeragiLaneState::default()
    }
}
fn append_sample(state: &mut SumeragiLaneState, pool: &AllocationBudget) -> Result<(), ()> {
    state.samples = state
        .samples
        .retain_and_append(sample(5), 2, pool)
        .map_err(|_| ())?;
    Ok(())
}
#[test]
fn sample_world_rollback_publication_and_readers_retain_original_pool() {
    const EXACT: &str = "state::lane_sample_owner_tests::sample_world_rollback_publication_and_readers_retain_original_pool";
    const CHILD: &str = "IROHA_CORE_SAMPLE_OWNER_TEST_CHILD";
    if std::env::var_os(CHILD).as_deref() != Some(std::ffi::OsStr::new(EXACT)) {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg(EXACT)
            .args(["--exact", "--nocapture", "--test-threads=1"])
            .env(CHILD, EXACT)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "original sample owner child failed\n{stdout}\n{stderr}"
        );
        assert!(
            stdout.contains(&format!("test {EXACT} ... ok"))
                && stdout.contains("test result: ok. 1 passed; 0 failed;"),
            "exact child did not finish\n{stdout}\n{stderr}"
        );
        return;
    }
    // EBR uses a process-global collector: isolate only this exact test so unrelated
    // test guards cannot postpone the reclamation these assertions measure.
    let pool = AllocationBudget::new(16 * 1024 * 1024);
    let mut world = crate::state::World::new();
    world.sumeragi_lanes = mv::cell::Cell::new(state(&pool));
    let reader = world.sumeragi_lanes.view();
    let pointer = reader.samples.as_ptr();
    let shells =
        super::world_journals::resources::WorldJournalShellReservation::try_reserve(&pool).unwrap();
    let mut block = world.try_block(&pool).unwrap();
    assert_eq!(block.sumeragi_lanes.get().samples.as_ptr(), pointer);
    let base = pool.reserved_bytes();
    pool.set_limit_bytes(base + demand(2) - 1);
    {
        let mut tx = block.sumeragi_lanes.transaction();
        assert_eq!(append_sample(tx.get_mut(), &pool), Err(()));
    }
    assert_eq!(block.sumeragi_lanes.get().samples.as_ptr(), pointer);
    assert_eq!(pool.reserved_bytes(), base);
    pool.set_limit_bytes(base + demand(2));
    {
        let mut tx = block.sumeragi_lanes.transaction();
        append_sample(tx.get_mut(), &pool).unwrap();
        assert_eq!(pool.reserved_bytes(), base + demand(2));
        // Successful work abandoned by its transaction must refund the new owner.
    }
    assert_eq!(block.sumeragi_lanes.get().samples.as_ptr(), pointer);
    assert_eq!(pool.reserved_bytes(), base);
    {
        let mut tx = block.sumeragi_lanes.transaction();
        append_sample(tx.get_mut(), &pool).unwrap();
        tx.apply();
    }
    let next_pointer = block.sumeragi_lanes.get().samples.as_ptr();
    let journal = block
        .try_detach_journals(shells, |_| Ok::<_, ()>(()))
        .unwrap();
    assert_eq!(reader.samples.as_ptr(), pointer);
    assert_eq!(world.sumeragi_lanes.view().samples.as_ptr(), pointer);
    pool.set_limit_bytes(0);
    let prepared = journal
        .try_prepare_publication(&world, |_, _| Ok::<_, ()>(()))
        .unwrap_or_else(|(_, error, _)| panic!("original prepaid publication: {error:?}"));
    drop(prepared.publish());
    assert_eq!(world.sumeragi_lanes.view().samples.as_ptr(), next_pointer);
    assert_eq!(reader.samples.as_ptr(), pointer);
    assert_eq!(reader.samples.len(), 3);
    assert!(pool.reserved_bytes() >= demand(3) + demand(2));
    drop(reader);
    drop(world);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while pool.reserved_bytes() != 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "original sample/World owners did not reclaim: {}",
            pool.reserved_bytes()
        );
        crossbeam_epoch::pin().flush();
        std::thread::yield_now();
    }
}
