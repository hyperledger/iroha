//! Prepaid Poseidon state, parameter upload, status, and output custody.

use iroha_accel::{
    HostOutput, PtxArtifact,
    cuda::{CudaDevice, CudaFailure, WorkRequest},
};
use std::ffi::c_void;

/// Exact public launch geometry; fault probes use the same bounded state backing.
#[derive(Clone, Copy)]
pub(super) struct Geometry {
    pub(super) width: usize,
    pub(super) count: usize,
    pub(super) stride: u32,
    pub(super) full_rounds: u32,
    pub(super) partial_rounds: u32,
}
impl Geometry {
    pub(super) fn canonical(width: usize, count: usize) -> Self {
        Self {
            width,
            count,
            stride: match width {
                3 => 12,
                6 => 24,
                _ => 0,
            },
            full_rounds: 8,
            partial_rounds: match width {
                3 => 57,
                6 => 60,
                _ => 0,
            },
        }
    }
    fn request(self) -> Option<(usize, usize, usize, WorkRequest)> {
        if !matches!(self.width, 3 | 6) || self.count == 0 || u32::try_from(self.count).is_err() {
            return None;
        }
        let state_words = self.count.checked_mul(self.width)?.checked_mul(4)?;
        let rounds = match self.width {
            3 => 65usize,
            6 => 68usize,
            _ => return None,
        };
        let constants = rounds.checked_mul(self.width)?.checked_mul(4)?;
        let mds = self.width.checked_mul(self.width)?.checked_mul(4)?;
        let buffers = state_words
            .checked_add(constants)?
            .checked_add(mds)?
            .checked_mul(8)?
            .checked_add(8)?;
        let host = state_words.checked_mul(8)?.checked_add(8)?;
        Some((
            state_words,
            constants,
            mds,
            WorkRequest {
                host_bytes: host,
                pinned_bytes: buffers,
                device_bytes: buffers,
            },
        ))
    }
}

pub(super) struct Output {
    pub(super) state: Option<HostOutput<u64>>,
    pub(super) status: [u32; 2],
}

/// Upload canonical words directly into prepaid pinned storage, then permute.
/// # Safety
/// The qualified artifact has the exact fixed Poseidon symbols and nine-argument
/// ABI. Generators must supply canonical four-limb field values and the current
/// Poseidon constants. Fault probes may only choose parameters rejected before
/// any out-of-bounds read or write by the admitted kernel's validation.
pub(super) unsafe fn output(
    device: &CudaDevice<'_>,
    artifact: PtxArtifact,
    geometry: Geometry,
    initial: impl FnMut(usize) -> u64,
    constants: impl FnMut(usize) -> u64,
    mds: impl FnMut(usize) -> u64,
) -> Result<Output, CudaFailure> {
    let (state_words, constant_words, mds_words, request) =
        geometry.request().ok_or(CudaFailure::InvalidRequest)?;
    let work = device.prepare(&[artifact], request)?;
    let mut state = work.buffer::<u64>(state_words)?;
    let mut round_constants = work.buffer::<u64>(constant_words)?;
    let mut matrix = work.buffer::<u64>(mds_words)?;
    let mut status = work.buffer::<u32>(2)?;
    work.upload_generated(&mut state, initial)?;
    work.wait()?;
    work.upload_generated(&mut round_constants, constants)?;
    work.wait()?;
    work.upload_generated(&mut matrix, mds)?;
    work.wait()?;
    work.upload(&mut status, &[0, 0])?;
    work.wait()?;
    let mut state_pointer = state.device_pointer();
    let mut constants_pointer = round_constants.device_pointer();
    let mut matrix_pointer = matrix.device_pointer();
    let mut status_pointer = status.device_pointer();
    let mut stride = geometry.stride;
    let mut count = geometry.count as u32;
    let mut flags = 0u32;
    let mut full = geometry.full_rounds;
    let mut partial = geometry.partial_rounds;
    let mut args = [
        (&raw mut state_pointer).cast::<c_void>(),
        (&raw mut stride).cast::<c_void>(),
        (&raw mut count).cast::<c_void>(),
        (&raw mut flags).cast::<c_void>(),
        (&raw mut constants_pointer).cast::<c_void>(),
        (&raw mut matrix_pointer).cast::<c_void>(),
        (&raw mut full).cast::<c_void>(),
        (&raw mut partial).cast::<c_void>(),
        (&raw mut status_pointer).cast::<c_void>(),
    ];
    let symbol = if geometry.width == 3 {
        c"poseidon2_permute_kernel"
    } else {
        c"poseidon6_permute_kernel"
    };
    // SAFETY: exact nine-argument kernel ABI and complete public checked geometry.
    unsafe {
        work.launch(
            artifact,
            symbol,
            [count.div_ceil(32), 1, 1],
            [32, 1, 1],
            0,
            &mut args,
        )?;
    }
    work.wait()?;
    // SAFETY: the uploaded two-word status is initialized on every kernel path.
    let returned_status = unsafe { work.download(&mut status)? };
    let status = [returned_status.as_slice()[0], returned_status.as_slice()[1]];
    let state = if status[0] == 0 {
        // SAFETY: state was completely uploaded before the admitted permutation.
        Some(unsafe { work.download(&mut state)? })
    } else {
        None
    };
    Ok(Output { state, status })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn complete_request_includes_constants_matrix_status_and_host_publication() {
        for width in [3, 6] {
            let (state, constants, mds, request) =
                Geometry::canonical(width, 257).request().unwrap();
            assert_eq!(state, 257 * width * 4);
            assert_eq!(constants, (if width == 3 { 65 } else { 68 }) * width * 4);
            assert_eq!(mds, width * width * 4);
            assert_eq!(request.host_bytes, state * 8 + 8);
            assert_eq!(request.pinned_bytes, (state + constants + mds) * 8 + 8);
            assert_eq!(request.pinned_bytes, request.device_bytes);
        }
    }
    #[test]
    fn invalid_geometry_does_not_reserve_native_storage() {
        assert!(Geometry::canonical(3, 0).request().is_none());
        assert!(Geometry::canonical(6, usize::MAX).request().is_none());
        assert!(Geometry::canonical(4, 1).request().is_none());
    }
}
