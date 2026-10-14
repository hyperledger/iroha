//! Named Sumeragi threads with an explicit, configured stack-size budget.

use iroha_config::parameters::defaults::concurrency as concurrency_defaults;
use std::sync::atomic::{AtomicUsize, Ordering};

static CONFIGURED_SUMERAGI_STACK_SIZE_BYTES: AtomicUsize = AtomicUsize::new(0);
fn normalized_sumeragi_stack_size_bytes(bytes: usize) -> Option<usize> {
    (concurrency_defaults::SUMERAGI_STACK_BYTES_MIN
        ..=concurrency_defaults::SUMERAGI_STACK_BYTES_MAX)
        .contains(&bytes)
        .then_some(bytes)
}
/// Override the stack size used for Sumeragi helper threads.
///
/// `irohad` applies this from the validated `concurrency.sumeragi_stack_bytes`
/// configuration before spawning consensus workers. Embedders that do not call
/// this setter receive the same deterministic configuration default.
pub fn set_sumeragi_stack_size_bytes(bytes: usize) {
    let bytes = normalized_sumeragi_stack_size_bytes(bytes)
        .unwrap_or(concurrency_defaults::SUMERAGI_STACK_BYTES);
    CONFIGURED_SUMERAGI_STACK_SIZE_BYTES.store(bytes, Ordering::Relaxed);
}
fn sumeragi_stack_size_bytes() -> usize {
    let configured = CONFIGURED_SUMERAGI_STACK_SIZE_BYTES.load(Ordering::Relaxed);
    normalized_sumeragi_stack_size_bytes(configured)
        .unwrap_or(concurrency_defaults::SUMERAGI_STACK_BYTES)
}
/// Build a named Sumeragi thread with an explicit stack-size budget.
///
/// Consensus execution must not rely on platform default stack sizing because
/// deep recovery and validation paths can exceed small default thread stacks.
pub(crate) fn sumeragi_thread_builder(name: impl Into<String>) -> std::thread::Builder {
    std::thread::Builder::new()
        .name(name.into())
        .stack_size(sumeragi_stack_size_bytes())
}
#[cfg(test)]
mod tests {
    use super::{
        CONFIGURED_SUMERAGI_STACK_SIZE_BYTES, concurrency_defaults,
        normalized_sumeragi_stack_size_bytes, set_sumeragi_stack_size_bytes,
        sumeragi_stack_size_bytes, sumeragi_thread_builder,
    };
    use std::sync::{Mutex, atomic::Ordering, mpsc};
    static STACK_CONFIG_TEST_LOCK: Mutex<()> = Mutex::new(());
    struct RestoreSumeragiStackSize(usize);
    impl Drop for RestoreSumeragiStackSize {
        fn drop(&mut self) {
            CONFIGURED_SUMERAGI_STACK_SIZE_BYTES.store(self.0, Ordering::Relaxed);
        }
    }
    #[test]
    fn sumeragi_thread_builder_applies_requested_thread_name() {
        let (name_tx, name_rx) = mpsc::sync_channel::<String>(1);
        let join = sumeragi_thread_builder("sumeragi-thread-builder-test")
            .spawn(move || {
                let thread_name = std::thread::current()
                    .name()
                    .expect("test thread name should be set")
                    .to_owned();
                let _ = name_tx.send(thread_name);
            })
            .expect("spawn test thread");
        let observed = name_rx.recv().expect("thread name message");
        join.join().expect("join test thread");
        assert_eq!(observed, "sumeragi-thread-builder-test");
    }
    #[test]
    fn sumeragi_stack_size_is_bounded() {
        assert_eq!(
            normalized_sumeragi_stack_size_bytes(concurrency_defaults::SUMERAGI_STACK_BYTES_MIN),
            Some(concurrency_defaults::SUMERAGI_STACK_BYTES_MIN)
        );
        assert_eq!(
            normalized_sumeragi_stack_size_bytes(concurrency_defaults::SUMERAGI_STACK_BYTES_MAX),
            Some(concurrency_defaults::SUMERAGI_STACK_BYTES_MAX)
        );
        assert_eq!(
            normalized_sumeragi_stack_size_bytes(
                concurrency_defaults::SUMERAGI_STACK_BYTES_MIN - 1
            ),
            None
        );
        assert_eq!(
            normalized_sumeragi_stack_size_bytes(
                concurrency_defaults::SUMERAGI_STACK_BYTES_MAX + 1
            ),
            None
        );
    }
    #[test]
    fn sumeragi_stack_size_uses_configured_value() {
        let _guard = STACK_CONFIG_TEST_LOCK.lock().expect("stack test lock");
        let previous = CONFIGURED_SUMERAGI_STACK_SIZE_BYTES.swap(0, Ordering::Relaxed);
        let _restore = RestoreSumeragiStackSize(previous);
        set_sumeragi_stack_size_bytes(concurrency_defaults::SUMERAGI_STACK_BYTES_MIN);
        assert_eq!(
            sumeragi_stack_size_bytes(),
            concurrency_defaults::SUMERAGI_STACK_BYTES_MIN
        );
        set_sumeragi_stack_size_bytes(usize::MAX);
        assert_eq!(
            sumeragi_stack_size_bytes(),
            concurrency_defaults::SUMERAGI_STACK_BYTES
        );
    }
}
