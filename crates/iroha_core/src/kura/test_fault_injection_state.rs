#[cfg(test)]
#[derive(Clone, Copy)]
struct ProgressAncestorSyncFault {
    target_index: usize,
    remaining_to_target: usize,
    failures_remaining: usize,
}
#[cfg(test)]
#[derive(Clone, Copy)]
struct ProgressIntentDirectorySyncFault {
    calls_before_failure: usize,
    target_index: usize,
}
#[cfg(test)]
std::thread_local! {
    static FAIL_NEXT_SIDECAR_PROMOTION_DIR_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_NEXT_SIDECAR_TEMP_MARKER_DIR_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_NEXT_INDEXED_SIDECAR_DATA_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_NEXT_INDEXED_SIDECAR_INITIAL_DATA_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_NEXT_INDEXED_SIDECAR_INDEX_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_NEXT_INDEXED_SIDECAR_DIR_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_NEXT_BOUND_PROGRESS_INTENT_FILE_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_AFTER_BOUND_PROGRESS_APPEND_BUILD_CALLS: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    static FAIL_NEXT_BOUND_PROGRESS_APPEND_DATA_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_NEXT_BOUND_PROGRESS_APPEND_INDEX_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_AFTER_NEXT_BOUND_EVIDENCE_TEMP_PREFIX: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    static FAIL_AFTER_NEXT_NATIVE_AMX_PUBLICATION_TEMP_PREFIX_AT_PATH: std::cell::RefCell<Option<(PathBuf, usize)>> = const { std::cell::RefCell::new(None) };
    static FAIL_AFTER_NEXT_NATIVE_AMX_EVIDENCE_TEMP_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_BOUND_PROGRESS_INTENT_DIRECTORY_SYNC: std::cell::Cell<Option<ProgressIntentDirectorySyncFault>> = const { std::cell::Cell::new(None) };
    static FAIL_PROGRESS_SIDECAR_ANCESTOR_SYNC_AT: std::cell::Cell<Option<ProgressAncestorSyncFault>> = const { std::cell::Cell::new(None) };
    static CERTIFIED_ARTIFACT_VALIDATION_COUNT: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    static FAIL_NEXT_CERTIFIED_LANE_BLOCK_ARTIFACT_VALIDATION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_AFTER_NEXT_CERTIFIED_FRONTIER_BUILD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_AFTER_NEXT_AUTONOMOUS_CERTIFIED_FRONTIER: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_NEXT_AUTONOMOUS_MERGE_BUNDLE_PERSISTENCE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_NEXT_AUTONOMOUS_MERGE_BUNDLE_APPEND_DATA_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_AFTER_NEXT_AUTONOMOUS_MERGE_BUNDLE_PAIR: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static LATEST_CERTIFIED_FRONTIER_POST_VALIDATION_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    static NATIVE_AMX_LATEST_INDEX_PRE_MUTATION_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce(&Path)>>> = const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
fn should_fail_after_bound_progress_append_build_for_tests() -> bool {
    FAIL_AFTER_BOUND_PROGRESS_APPEND_BUILD_CALLS.with(|slot| match slot.get() {
        Some(0) => {
            slot.set(None);
            true
        }
        Some(remaining) => {
            slot.set(Some(remaining - 1));
            false
        }
        None => false,
    })
}
const CANONICAL_HASH_READER_OBSERVED: usize = 1 << 0;
const CANONICAL_BLOCK_READER_OBSERVED: usize = 1 << 1;
