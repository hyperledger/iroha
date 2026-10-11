//! AES Metal attempts retain native output until caller-owned publication.

use super::MetalBuffer;
use super::metal_cost::AesCpuBaseline;
use super::{
    MetalKernel, metal_dispatch, metal_input_buffer, metal_output_buffer, metal_runtime_allowed,
    with_metal_state_try,
};
use objc2::rc::autoreleasepool;
use objc2_foundation::NSUInteger;
use objc2_metal::MTLBuffer as _;

enum Comparison {
    Measured(AesCpuBaseline),
    #[cfg(test)]
    Qualification,
}

impl Comparison {
    fn is_current(&self) -> bool {
        match self {
            Self::Measured(baseline) => baseline.is_current(),
            #[cfg(test)]
            Self::Qualification => true,
        }
    }
}

struct Output {
    selection: super::MetalSelection,
    buffer: MetalBuffer,
    blocks: usize,
    comparison: Comparison,
}

impl Output {
    fn copy_into(self, destination: &mut [[u8; 16]]) -> bool {
        let Self {
            selection,
            buffer,
            blocks,
            comparison,
        } = self;
        selection
            .run(|| {
                if blocks != destination.len() || !buffer.usable() || !comparison.is_current() {
                    return false;
                }
                // SAFETY: the completed kernel initialized exactly `blocks` contiguous
                // byte arrays. The retained native buffer outlives the entire copy.
                let completed = unsafe {
                    std::slice::from_raw_parts(
                        buffer.contents().as_ptr().cast::<[u8; 16]>(),
                        blocks,
                    )
                };
                destination.copy_from_slice(completed);
                true
            })
            .unwrap_or(false)
    }
}

fn kernel(decrypt: bool, fused: bool) -> MetalKernel {
    match (decrypt, fused) {
        (false, false) => MetalKernel::AesEncBatch,
        (true, false) => MetalKernel::AesDecBatch,
        (false, true) => MetalKernel::AesEncRounds,
        (true, true) => MetalKernel::AesDecRounds,
    }
}

fn attempt(
    states: &[[u8; 16]],
    keys: &[[u8; 16]],
    decrypt: bool,
    fused: bool,
    receipt: Option<MetalKernel>,
    comparison: Comparison,
) -> Option<Output> {
    if !metal_runtime_allowed()
        || states.is_empty()
        || keys.is_empty()
        || (!fused && keys.len() != 1)
    {
        return None;
    }
    let rounds = u32::try_from(keys.len()).ok()?;
    let blocks = NSUInteger::try_from(states.len()).ok()?;
    let output_bytes = states.len().checked_mul(16)?;
    autoreleasepool(|_| {
        with_metal_state_try(|ctx| {
            // Borrow the existing contiguous arrays; no flattened host copy or
            // uncharged Vec escapes from the native attempt.
            let input = metal_input_buffer(&ctx.device, states.as_flattened(), output_bytes)?;
            let keys = metal_input_buffer(
                &ctx.device,
                keys.as_flattened(),
                keys.len().checked_mul(16)?,
            )?;
            let output = metal_output_buffer(&ctx.device, output_bytes)?;
            let pipeline = match (decrypt, fused) {
                (false, false) => &ctx.aesenc_batch,
                (true, false) => &ctx.aesdec_batch,
                (false, true) => &ctx.aesenc_rounds,
                (true, true) => &ctx.aesdec_rounds,
            };
            if fused {
                let rounds =
                    metal_input_buffer(&ctx.device, &[rounds], std::mem::size_of::<u32>())?;
                metal_dispatch(
                    &ctx.queue,
                    pipeline,
                    &[&input, &keys, &output, &rounds],
                    blocks,
                    1,
                    "metal AES fused batch",
                    receipt,
                )?;
            } else {
                metal_dispatch(
                    &ctx.queue,
                    pipeline,
                    &[&input, &keys, &output],
                    blocks,
                    1,
                    "metal AES round batch",
                    receipt,
                )?;
            }
            Some(Output {
                selection: super::metal_runtime::current_selection()?,
                buffer: output,
                blocks: states.len(),
                comparison,
            })
        })
    })
}

#[cfg(test)]
fn with_receipt_into(
    states: &[[u8; 16]],
    keys: &[[u8; 16]],
    destination: &mut [[u8; 16]],
    decrypt: bool,
    fused: bool,
    receipt: Option<MetalKernel>,
) -> bool {
    if states.len() != destination.len() || (!fused && keys.len() != 1) {
        return false;
    }
    if states.is_empty() {
        return true;
    }
    if keys.is_empty() {
        destination.copy_from_slice(states);
        return true;
    }
    attempt(
        states,
        keys,
        decrypt,
        fused,
        receipt,
        Comparison::Qualification,
    )
    .is_some_and(|output| output.copy_into(destination))
}

/// Qualified public work and CPU comparison retained through native publication.
pub(crate) struct MetalAesSelection {
    selection: super::MetalSelection,
    baseline: AesCpuBaseline,
    blocks: usize,
}

impl MetalAesSelection {
    pub(super) fn new(
        selection: super::MetalSelection,
        baseline: AesCpuBaseline,
        blocks: usize,
    ) -> Option<Self> {
        (baseline.work().geometry_supported(blocks) && baseline.is_current()).then_some(Self {
            selection,
            baseline,
            blocks,
        })
    }

    /// Only the measured public geometry can consume this exact physical owner.
    pub(crate) fn run(self, states: &mut [[u8; 16]], keys: &[[u8; 16]]) -> bool {
        if states.len() != self.blocks || keys.len() != self.baseline.work().rounds() {
            return false;
        }
        self.selection
            .run(|| measured_in_place(states, keys, self.baseline))
            .unwrap_or(false)
    }
}

/// Production and calibration use the same baseline-bound in-place adapter.
pub(super) fn measured_in_place(
    states: &mut [[u8; 16]],
    keys: &[[u8; 16]],
    baseline: AesCpuBaseline,
) -> bool {
    let work = baseline.work();
    if !work.geometry_supported(states.len())
        || keys.len() != work.rounds()
        || !baseline.is_current()
    {
        return false;
    }
    attempt(
        states,
        keys,
        work.decrypt(),
        work.fused(),
        Some(kernel(work.decrypt(), work.fused())),
        Comparison::Measured(baseline),
    )
    .is_some_and(|output| output.copy_into(states))
}

// Direct required-hardware controls exercise qualified physical kernels without
// pretending that a public workload cost profile selected them.
#[cfg(all(test, feature = "metal-hardware-tests"))]
pub(crate) fn metal_aes_batch_in_place(
    states: &mut [[u8; 16]],
    keys: &[[u8; 16]],
    decrypt: bool,
    fused: bool,
) -> bool {
    if !fused && keys.len() != 1 {
        return false;
    }
    if states.is_empty() || keys.is_empty() {
        return true;
    }
    attempt(
        states,
        keys,
        decrypt,
        fused,
        Some(kernel(decrypt, fused)),
        Comparison::Qualification,
    )
    .is_some_and(|output| output.copy_into(states))
}

/// Attempt one AESENC batch; refusal or failure preserves the caller destination.
#[cfg(test)]
pub fn metal_aesenc_batch_into(
    states: &[[u8; 16]],
    key: [u8; 16],
    destination: &mut [[u8; 16]],
) -> bool {
    with_receipt_into(
        states,
        &[key],
        destination,
        false,
        false,
        Some(MetalKernel::AesEncBatch),
    )
}
/// Attempt one AESDEC batch; refusal or failure preserves the caller destination.
#[cfg(test)]
pub fn metal_aesdec_batch_into(
    states: &[[u8; 16]],
    key: [u8; 16],
    destination: &mut [[u8; 16]],
) -> bool {
    with_receipt_into(
        states,
        &[key],
        destination,
        true,
        false,
        Some(MetalKernel::AesDecBatch),
    )
}
/// Attempt ordered AESENC rounds; refusal or failure preserves the caller destination.
#[cfg(test)]
pub fn metal_aesenc_rounds_batch_into(
    states: &[[u8; 16]],
    keys: &[[u8; 16]],
    destination: &mut [[u8; 16]],
) -> bool {
    with_receipt_into(
        states,
        keys,
        destination,
        false,
        true,
        Some(MetalKernel::AesEncRounds),
    )
}
/// Attempt ordered AESDEC rounds; refusal or failure preserves the caller destination.
#[cfg(test)]
pub fn metal_aesdec_rounds_batch_into(
    states: &[[u8; 16]],
    keys: &[[u8; 16]],
    destination: &mut [[u8; 16]],
) -> bool {
    with_receipt_into(
        states,
        keys,
        destination,
        true,
        true,
        Some(MetalKernel::AesDecRounds),
    )
}

#[cfg(test)]
#[path = "metal_aes/tests.rs"]
mod tests;
