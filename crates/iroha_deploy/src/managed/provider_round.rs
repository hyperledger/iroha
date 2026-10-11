//! Fixed three-provider scheduling; all operation authority stays with each original caller.

use std::thread;

/// Join every started worker before selecting a result in original provider order. Serial
/// recovery and active thread-local Norito limits retain the original short-circuit recipe.
/// The caller owns entry/exit deadlines, cancellation and all native custody/proof checks.
pub(super) fn run<T: Send, R: Send, E: Send>(
    inputs: [T; 3],
    parallel: bool,
    action: impl Fn(T) -> Result<R, E> + Sync,
    worker_failed: impl Fn() -> E + Sync,
) -> Result<[R; 3], E> {
    if !parallel || norito::core::decode_limits_active() {
        let [first, second, third] = inputs;
        return Ok([action(first)?, action(second)?, action(third)?]);
    }
    thread::scope(|scope| {
        let action = &action;
        let handles =
            inputs.map(|input| thread::Builder::new().spawn_scoped(scope, move || action(input)));
        // Do not use `?` until every handle is consumed, even when an earlier worker failed
        // to start, panicked, or returned an ordinary refusal. No task can outlive its inputs.
        let results = handles.map(|handle| match handle {
            Ok(handle) => handle.join().unwrap_or_else(|_| Err(worker_failed())),
            Err(_) => Err(worker_failed()),
        });
        let [first, second, third] = results;
        Ok([first?, second?, third?])
    })
}

#[cfg(test)]
#[path = "provider_round_tests.rs"]
mod tests;
