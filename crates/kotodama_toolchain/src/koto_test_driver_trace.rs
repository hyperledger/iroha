//! Immutable original-pool trace custody for nested test reports and checkpoints.

use super::{IVM, KotoTestHost, TraceMode};
use ivm::{VMError, zk::RuntimeTraceCapture};

/// Execution traces of one test, kept apart by program so PCs are never mapped against the wrong
/// source map: the test function runs in the test projection, seiyaku calls in the runtime
/// artifact.
#[derive(Clone, Debug, Default)]
pub(super) struct TestTrace {
    /// Steps executed by the test function itself.
    pub(super) harness: Option<RuntimeTraceCapture>,
    /// Steps executed by nested seiyaku calls, concatenated in call order.
    pub(super) runtime: Option<RuntimeTraceCapture>,
}

/// Retain the test function's trace and the completed nested observations separately.
pub(super) fn capture_report(
    vm: &IVM,
    supplemental: Option<&RuntimeTraceCapture>,
) -> Result<TestTrace, VMError> {
    let harness = if vm.trace_mode() == TraceMode::Off {
        None
    } else {
        Some(vm.try_runtime_trace_capture()?)
    };
    if let (Some(harness), Some(nested)) = (harness.as_ref(), supplemental) {
        // Both programs must have run in one funded pool; a foreign-pool nested owner is refused
        // exactly as report composition refuses it.
        drop(harness.try_combine(nested)?);
    }
    Ok(TestTrace {
        harness,
        runtime: supplemental.cloned(),
    })
}

impl KotoTestHost {
    /// Fund the complete replacement before changing any retained report owner.
    ///
    /// Returns the number of trace steps the nested call contributed.
    pub(super) fn record_nested_trace(&mut self, nested_vm: &IVM) -> Result<usize, VMError> {
        if nested_vm.trace_mode() == TraceMode::Off {
            return Ok(0);
        }
        let following = nested_vm.try_runtime_trace_capture()?;
        let steps = following.delta_len();
        let replacement = match self.supplemental_trace.as_ref() {
            Some(prior) => prior.try_combine(&following)?,
            None => following,
        };
        self.supplemental_trace = Some(replacement);
        Ok(steps)
    }
}

#[cfg(test)]
#[path = "koto_test_driver_trace_tests.rs"]
mod tests;
