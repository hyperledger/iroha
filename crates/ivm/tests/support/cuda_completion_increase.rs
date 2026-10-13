//! Exact original-owner credit checks for native CUDA parity controls.

use ivm::{CudaCompletionSnapshot, CudaKernel};

/// Require increased completion credit for this kernel on the same original owner.
pub fn increased(before: &[Option<CudaCompletionSnapshot>], kernel: CudaKernel) -> bool {
    before.iter().enumerate().any(|(slot, previous)| {
        let Some(after) =
            ivm::cuda_completion_snapshot(slot).expect("completion registry must be readable")
        else {
            return false;
        };
        if let Some(previous) = previous {
            assert_eq!(
                previous.device(),
                after.device(),
                "physical owner cannot be replaced"
            );
        }
        after.completed(kernel) > previous.map_or(0, |value| value.completed(kernel))
    })
}
