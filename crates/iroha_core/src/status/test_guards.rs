#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TestLockOwner {
    Task(tokio::task::Id),
    Thread(std::thread::ThreadId),
}
#[cfg(test)]
thread_local! {
    static TEST_LOCK_OWNER_OVERRIDE: std::cell::Cell<Option<TestLockOwner>> =
        const { std::cell::Cell::new(None) };
}
#[cfg(test)]
impl TestLockOwner {
    fn current() -> Self {
        if let Some(owner) = TEST_LOCK_OWNER_OVERRIDE.with(std::cell::Cell::get) {
            return owner;
        }
        tokio::task::try_id().map_or_else(|| Self::Thread(std::thread::current().id()), Self::Task)
    }
}
#[cfg(test)]
#[derive(Default)]
struct TestLockState {
    owner: Option<TestLockOwner>,
    depth: usize,
}
#[cfg(test)]
#[derive(Default)]
pub(crate) struct TestLock {
    state: Mutex<TestLockState>,
    cvar: Condvar,
}
#[cfg(test)]
pub(crate) struct TestLockGuard {
    lock: &'static TestLock,
    owner: TestLockOwner,
}
#[cfg(test)]
impl Drop for TestLockGuard {
    fn drop(&mut self) {
        let mut state = self
            .lock
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.owner == Some(self.owner) {
            state.depth = state.depth.saturating_sub(1);
            if state.depth == 0 {
                state.owner = None;
                self.lock.cvar.notify_one();
            }
        }
    }
}
#[cfg(test)]
static STATUS_TEST_GLOBAL_LOCK: OnceLock<TestLock> = OnceLock::new();
#[cfg(test)]
pub(crate) static OPERATOR_STATUS_TEST_LOCK: OnceLock<TestLock> = OnceLock::new();
#[cfg(test)]
static PEER_KEY_POLICY_TEST_LOCK: OnceLock<TestLock> = OnceLock::new();
#[cfg(test)]
static LOCAL_REMOVED_TEST_LOCK: OnceLock<TestLock> = OnceLock::new();
#[cfg(test)]
fn canonical_test_lock(_: &'static OnceLock<TestLock>) -> &'static TestLock {
    STATUS_TEST_GLOBAL_LOCK.get_or_init(TestLock::default)
}
#[cfg(test)]
pub(crate) fn reentrant_test_guard(lock: &'static OnceLock<TestLock>) -> TestLockGuard {
    let owner = TestLockOwner::current();
    let lock = canonical_test_lock(lock);
    let mut state = lock
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    loop {
        match state.owner {
            None => {
                state.owner = Some(owner);
                state.depth = 1;
                break;
            }
            Some(current) if current == owner => {
                state.depth = state.depth.saturating_add(1);
                break;
            }
            Some(_) => {
                state = lock
                    .cvar
                    .wait(state)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
        }
    }
    TestLockGuard { lock, owner }
}
#[cfg(test)]
pub(crate) fn try_reentrant_test_guard(lock: &'static OnceLock<TestLock>) -> Option<TestLockGuard> {
    let owner = TestLockOwner::current();
    let lock = canonical_test_lock(lock);
    let mut state = lock
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match state.owner {
        None => {
            state.owner = Some(owner);
            state.depth = 1;
            Some(TestLockGuard { lock, owner })
        }
        Some(current) if current == owner => {
            state.depth = state.depth.saturating_add(1);
            Some(TestLockGuard { lock, owner })
        }
        Some(_) => None,
    }
}
#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct NexusFeeTestLock;
#[cfg(test)]
pub(crate) struct NexusFeeTestGuard {
    _guard: TestLockGuard,
}
#[cfg(test)]
impl NexusFeeTestLock {
    pub(crate) fn lock(self) -> Result<NexusFeeTestGuard, std::convert::Infallible> {
        Ok(NexusFeeTestGuard {
            _guard: reentrant_test_guard(&OPERATOR_STATUS_TEST_LOCK),
        })
    }
}
#[cfg(test)]
/// Serialize process-wide operator status mutations with tests that need a
/// stable clear/publish/observe window.
///
/// This is a synchronous, owner-reentrant test lease. Do not move it to another
/// task or thread for nested use, hold it across `.await`, or wait for a child
/// which can call a guarded status mutation; each of those patterns can prevent
/// the original owner from releasing the lease.
pub(crate) fn operator_status_test_guard() -> TestLockGuard {
    reentrant_test_guard(&OPERATOR_STATUS_TEST_LOCK)
}
#[cfg(test)]
pub(crate) fn peer_key_policy_test_guard() -> TestLockGuard {
    reentrant_test_guard(&PEER_KEY_POLICY_TEST_LOCK)
}
#[cfg(test)]
pub(crate) fn local_removed_test_guard() -> TestLockGuard {
    reentrant_test_guard(&LOCAL_REMOVED_TEST_LOCK)
}
#[cfg(test)]
/// Reset settlement telemetry counters for isolated tests.
pub fn settlement_status_reset_for_tests() {
    *lock_operator_status_slot(settlement_status_slot(), "settlement status") =
        SettlementStatusState::default();
}
