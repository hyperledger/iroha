//! Qualified native Ed25519 attempts and caller-owned publication.

use super::policy::{Kernel, public_workload_task_id};
use crate::signature::{BatchInput, Ed25519BatchItem};
use iroha_accel::{HostOutput, cuda::CudaFailure};

#[path = "signature_launch.rs"]
mod launch;

fn stage(input: BatchInput<'_, '_>) -> Result<HostOutput<u8>, CudaFailure> {
    let count = input.checked_len().ok_or(CudaFailure::InvalidRequest)?;
    let artifact = crate::cuda_artifact::artifact(Kernel::Ed25519)?;
    match crate::cuda_dispatch::with_selected(Kernel::Ed25519, artifact, |device| {
        // SAFETY: exact embedded artifact and fixed-width input generators own
        // the kernel ABI. All original inputs remain borrowed through completion.
        unsafe {
            launch::signature_output(
                device,
                artifact,
                count,
                |i| input.signature(i),
                |i| input.public_key(i),
                |i| input.hram(i),
            )
        }
    }) {
        Ok(output) if output.len() == count && output.iter().all(|&byte| byte <= 1) => {
            super::imp::record_completed_cuda_dispatch(Kernel::Ed25519, artifact);
            Ok(output)
        }
        Ok(_) => {
            crate::cuda_dispatch::quarantine_current_kernel();
            Err(CudaFailure::Quarantined)
        }
        Err(error) => {
            if !matches!(
                error,
                CudaFailure::Capacity | CudaFailure::Busy | CudaFailure::Unavailable
            ) {
                crate::cuda_dispatch::quarantine_current_kernel();
            }
            Err(error)
        }
    }
}

pub(super) fn admit() -> bool {
    let Ok(artifact) = crate::cuda_artifact::artifact(Kernel::Ed25519) else {
        return false;
    };
    crate::cuda_dispatch::admit_kernel(Kernel::Ed25519, artifact, || {
        use ed25519_dalek::{Signer, SigningKey};
        let Some(_guard) = super::imp::SelftestRunningGuard::enter() else {
            return Err(CudaFailure::Busy);
        };
        let key = SigningKey::from_bytes(&[0x51; 32]);
        let message = b"IVM native Ed25519 admission";
        let mut bad = key.sign(message).to_bytes();
        bad[40] ^= 1;
        use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION};
        let valid = Ed25519BatchItem {
            message,
            signature: key.sign(message).to_bytes(),
            public_key: key.verifying_key().to_bytes(),
        };
        let mut items: [Ed25519BatchItem<'_>; 10] = std::array::from_fn(|_| valid);
        items[1].signature = bad;
        items[2].signature = [0; 64];
        items[3].public_key = [0; 32];
        items[4].public_key = EIGHT_TORSION[1].compress().to_bytes();
        items[5].public_key = (ED25519_BASEPOINT_POINT + EIGHT_TORSION[1])
            .compress()
            .to_bytes();
        items[6].signature[..32].copy_from_slice(&EIGHT_TORSION[1].compress().to_bytes());
        let mut noncanonical = [0xff; 32];
        noncanonical[0] = 0xee;
        noncanonical[31] = 0x7f;
        items[7].signature[..32].copy_from_slice(&noncanonical);
        items[8].public_key = noncanonical;
        items[9].signature[32..].copy_from_slice(&[
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ]);
        let expected = std::array::from_fn::<_, 10, _>(|index| {
            let item = &items[index];
            crate::signature::verify_signature(
                crate::signature::SignatureScheme::Ed25519,
                item.message,
                &item.signature,
                &item.public_key,
            )
        });
        if expected
            != [
                true, false, false, false, false, false, false, false, false, false,
            ]
        {
            return Ok(false);
        }
        let input = BatchInput::Items(&items);
        let native = stage(input)?;
        let mut output = [false; 10];
        Ok(input.publish(&native, &mut output) && output == expected)
    })
}

fn into(input: BatchInput<'_, '_>, destination: &mut [bool]) -> bool {
    if input.checked_len() != Some(destination.len()) {
        return false;
    }
    if destination.is_empty() {
        return true;
    }
    if launch::request(destination.len()).is_none() {
        return false;
    }
    let task = public_workload_task_id(0x0f0f_0f0f_0000_0071, &[destination.len() as u64]);
    crate::cuda_dispatch::with_task_scope(task, || {
        super::imp::record_cuda_attempt();
        if !super::imp::ensure_cuda_kernel(Kernel::Ed25519) {
            return false;
        }
        let Ok(native) = stage(input) else {
            return false;
        };
        input.publish(&native, destination)
    })
}

/// Attempt an exact prepared batch. Refusal leaves the destination unchanged;
/// success includes the same strict encoding checks as ordinary verification.
pub fn ed25519_verify_batch_cuda_into(
    signatures: &[[u8; 64]],
    public_keys: &[[u8; 32]],
    hrams: &[[u8; 32]],
    destination: &mut [bool],
) -> bool {
    into(
        BatchInput::Prepared {
            signatures,
            public_keys,
            hrams,
        },
        destination,
    )
}

/// Generate challenges in prepaid native staging from the original entries.
pub(crate) fn ed25519_items_cuda_into(
    items: &[Ed25519BatchItem<'_>],
    destination: &mut [bool],
) -> bool {
    into(BatchInput::Items(items), destination)
}

/// Attempt one signature; `Some` requires a completed qualified native attempt.
pub fn ed25519_verify_cuda(
    message: &[u8],
    signature: &[u8; 64],
    public_key: &[u8; 32],
) -> Option<bool> {
    let items = [Ed25519BatchItem {
        message,
        signature: *signature,
        public_key: *public_key,
    }];
    let mut output = [false];
    ed25519_items_cuda_into(&items, &mut output).then_some(output[0])
}
