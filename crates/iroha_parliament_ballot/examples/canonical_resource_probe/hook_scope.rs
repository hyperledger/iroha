//! Retire the decoder's first-use global hook within the charged one-shot interval.
//!
//! Norito installs a process-wide hook which owns its captured predecessor. This
//! isolated diagnostic restores that exact predecessor after the operation and
//! drops both installed forwarding closures before allocation routing ends. The
//! decoder's initialized OnceLock is not reset: no later decode or concurrent
//! application work is permitted in this one-shot process.

use std::{
    panic::{self, AssertUnwindSafe, PanicHookInfo},
    sync::Arc,
};

type Hook = Box<dyn Fn(&PanicHookInfo<'_>) + Send + Sync + 'static>;

/// Run under the original hook's behavior, then restore its exact owned object.
///
/// The caller enters ACTIVE before this function and leaves it only after all
/// copied inputs and this result have been dropped. No decoder is prewarmed.
/// Catching the operation first is necessary because take_hook/set_hook cannot
/// run from a panicking thread; an ordinary unwind-time Drop guard is unsuitable.
/// A caught panic's payload is destroyed here, never returned outside ACTIVE.
pub fn run<T>(operation: impl FnOnce() -> T) -> Result<T, ()> {
    let original: Arc<Hook> = Arc::new(panic::take_hook());
    let forwarding = Arc::clone(&original);
    panic::set_hook(Box::new(move |info| forwarding(info)));

    let result = panic::catch_unwind(AssertUnwindSafe(operation));

    // This drops Norito's newly installed hook, if reached, and the forwarding
    // closure it captured. The original remains owned by our sole Arc below.
    drop(panic::take_hook());
    let original = match Arc::try_unwrap(original) {
        Ok(original) => original,
        Err(_) => {
            // An escaped hook owner violates this isolated one-shot contract.
            // Do not claim cleanup or continue with a retained arena owner.
            unsafe { libc::_exit(74) };
        }
    };
    panic::set_hook(original);
    match result {
        Ok(value) => Ok(value),
        Err(payload) => {
            drop(payload);
            Err(())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        process::Command,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use super::*;

    const CHILD_MODE: &str = "PARLIAMENT_CANONICAL_HOOK_TEST";
    const TEST_NAME: &str = "hook_scope::tests::restores_original_and_drops_installed_hook";

    struct CountDrop(Arc<AtomicUsize>);

    impl Drop for CountDrop {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn child_case(mode: &str) {
        let baseline = panic::take_hook();
        let calls = Arc::new(AtomicUsize::new(0));
        let forwarded_calls = Arc::clone(&calls);
        let hook: Hook = Box::new(move |_| {
            forwarded_calls.fetch_add(1, Ordering::SeqCst);
        });
        let original_address = std::ptr::from_ref(hook.as_ref()).cast::<()>();
        panic::set_hook(hook);
        let drops = Arc::new(AtomicUsize::new(0));
        let operation = || match mode {
            "decode" => {
                // Actual canonical decode reaches Norito's original hook install.
                // Encoding is also inside the operation; nothing is prewarmed.
                let bytes = norito::encode_canonical(&17_u32).unwrap();
                assert_eq!(norito::decode_canonical::<u32>(&bytes).unwrap(), 17);
                17
            }
            "panic" => panic::panic_any(CountDrop(Arc::clone(&drops))),
            "ordinary" => {
                // Simulate another installed closure with an owned drop witness.
                let predecessor = panic::take_hook();
                let witness = CountDrop(Arc::clone(&drops));
                panic::set_hook(Box::new(move |info| {
                    let _ = &witness;
                    predecessor(info);
                }));
                17
            }
            _ => panic!("unknown isolated hook test case"),
        };
        let result = run(operation);
        let restored = panic::take_hook();
        let restored_address = std::ptr::from_ref(restored.as_ref()).cast::<()>();
        // Restore the harness hook before assertions can panic.
        panic::set_hook(baseline);
        drop(restored);
        assert_eq!(original_address, restored_address);
        assert_eq!(Arc::strong_count(&calls), 1);
        assert_eq!(result, if mode == "panic" { Err(()) } else { Ok(17) });
        assert_eq!(calls.load(Ordering::SeqCst), usize::from(mode == "panic"));
        assert_eq!(drops.load(Ordering::SeqCst), usize::from(mode != "decode"));
    }

    #[test]
    fn restores_original_and_drops_installed_hook() {
        if let Ok(mode) = std::env::var(CHILD_MODE) {
            child_case(&mode);
            return;
        }
        for mode in ["decode", "panic", "ordinary"] {
            let output = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST_NAME, "--test-threads=1", "--nocapture"])
                .env(CHILD_MODE, mode)
                .output()
                .unwrap();
            assert!(output.status.success(), "isolated {mode}: {output:?}");
            assert!(output.stderr.is_empty(), "isolated {mode}: {output:?}");
            let stdout = String::from_utf8(output.stdout).unwrap();
            assert!(stdout.contains("1 passed"), "isolated {mode}: {stdout}");
        }
    }
}
