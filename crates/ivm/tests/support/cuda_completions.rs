//! Exact owner/kernel completion observations for native parity controls.

use ivm::CudaCompletionSnapshot;

/// Read every observed stable slot without interpreting local contention as zero.
pub fn capture() -> Vec<Option<CudaCompletionSnapshot>> {
    (0..ivm::cuda_device_slots())
        .map(|slot| {
            ivm::cuda_completion_snapshot(slot).expect("completion registry must be readable")
        })
        .collect()
}
