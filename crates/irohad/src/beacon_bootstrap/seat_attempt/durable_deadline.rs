//! Frozen same-boot native expiry; Unix time cannot extend a restarted attempt.

use super::*;
use iroha_primitives::time::native_continuous_clock_nanos;
use norito::{NoritoDeserialize, NoritoSchema, NoritoSerialize};
use std::result::Result;

#[derive(Clone, Copy, Debug, PartialEq, Eq, NoritoSerialize, NoritoDeserialize, NoritoSchema)]
#[norito_schema(name = "irohad::beacon_bootstrap::seat_attempt::DurableDeadlineV1")]
#[norito(decode_fields)]
pub(super) struct DurableDeadline {
    pub(super) boot: [u8; 32],
    pub(super) origin_nanos: u128,
    pub(super) expiry_nanos: u128,
}
impl DurableDeadline {
    /// Sample the real clock before measuring the remaining admitted interval.
    /// The resulting deadline is conservatively no later than the original one.
    pub(super) fn freeze(deadline: Instant) -> Result<Self, AttemptError> {
        let boot = boot_identity().map_err(|_| AttemptError::Deadline)?;
        let origin_nanos = native_continuous_clock_nanos().map_err(|_| AttemptError::Deadline)?;
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(AttemptError::Deadline)?;
        if remaining.is_zero() {
            return Err(AttemptError::Deadline);
        }
        let expiry_nanos = origin_nanos
            .checked_add(remaining.as_nanos())
            .ok_or(AttemptError::Deadline)?;
        Ok(Self {
            boot,
            origin_nanos,
            expiry_nanos,
        })
    }
    /// Verify the actual OS boot and native clock, then tighten the caller's deadline.
    /// Unsupported/changed clock origins, regression and expiry all fail closed.
    pub(super) fn restore(&self, supplied: Instant) -> Result<Instant, AttemptError> {
        #[cfg(all(test, sumeragi_daemon_mutation = "HC107"))]
        {
            return Ok(supplied);
        }
        let boot = boot_identity().map_err(|_| AttemptError::Deadline)?;
        let now = native_continuous_clock_nanos().map_err(|_| AttemptError::Deadline)?;
        self.remaining_at(boot, now).and_then(|remaining| {
            // Sample Instant first: any elapsed time before this conversion tightens,
            // rather than extends, the original suspend-inclusive expiry.
            let anchor = Instant::now();
            let after = native_continuous_clock_nanos().map_err(|_| AttemptError::Deadline)?;
            let elapsed = after.checked_sub(now).ok_or(AttemptError::Deadline)?;
            let remaining = remaining
                .checked_sub(duration(elapsed)?)
                .ok_or(AttemptError::Deadline)?;
            anchor
                .checked_add(remaining)
                .map(|original| original.min(supplied))
                .ok_or(AttemptError::Deadline)
        })
    }
    fn remaining_at(&self, boot: [u8; 32], now: u128) -> Result<Duration, AttemptError> {
        if boot != self.boot || now < self.origin_nanos || now >= self.expiry_nanos {
            return Err(AttemptError::Deadline);
        }
        duration(self.expiry_nanos - now)
    }
}
fn duration(nanos: u128) -> Result<Duration, AttemptError> {
    Ok(Duration::new(
        u64::try_from(nanos / 1_000_000_000).map_err(|_| AttemptError::Deadline)?,
        u32::try_from(nanos % 1_000_000_000).map_err(|_| AttemptError::Deadline)?,
    ))
}

#[cfg(target_os = "macos")]
#[allow(
    unsafe_code,
    reason = "the OS boot-session UUID is supplied by the native sysctl API"
)]
fn boot_identity() -> std::io::Result<[u8; 32]> {
    unsafe extern "C" {
        fn sysctlbyname(
            name: *const std::ffi::c_char,
            old: *mut std::ffi::c_void,
            length: *mut usize,
            new: *mut std::ffi::c_void,
            new_length: usize,
        ) -> std::ffi::c_int;
    }
    let mut bytes = [0u8; 64];
    let mut length = bytes.len();
    // SAFETY: exact initialized writable buffer/length, constant NUL name and no write request.
    if unsafe {
        sysctlbyname(
            c"kern.bootsessionuuid".as_ptr(),
            bytes.as_mut_ptr().cast(),
            &raw mut length,
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    if length != 37 || bytes[36] != 0 {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    uuid_hash(&bytes[..36])
}
#[cfg(target_os = "linux")]
fn boot_identity() -> std::io::Result<[u8; 32]> {
    use std::io::Read as _;
    let mut file = File::open("/proc/sys/kernel/random/boot_id")?;
    let mut bytes = [0u8; 38];
    let mut used = 0;
    while used < bytes.len() {
        let n = file.read(&mut bytes[used..])?;
        if n == 0 {
            break;
        }
        used += n;
    }
    if used != 37 || bytes[36] != b'\n' {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    uuid_hash(&bytes[..36])
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn boot_identity() -> std::io::Result<[u8; 32]> {
    Err(std::io::ErrorKind::Unsupported.into())
}
fn uuid_hash(bytes: &[u8]) -> std::io::Result<[u8; 32]> {
    if bytes.len() != 36
        || bytes.iter().enumerate().any(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                *byte != b'-'
            } else {
                !byte.is_ascii_hexdigit()
            }
        })
    {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    Ok(Hash::new_from_chunks(&[b"iroha.dkg.attempt.boot-origin.v1\0", bytes]).into())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_native_expiry_rejects_changed_boot_regression_and_exhaustion() {
        let record = DurableDeadline {
            boot: [1; 32],
            origin_nanos: 100,
            expiry_nanos: 200,
        };
        assert_eq!(
            record.remaining_at([1; 32], 199).unwrap(),
            Duration::from_nanos(1)
        );
        for (boot, time) in [
            ([2; 32], 150),
            ([1; 32], 99),
            ([1; 32], 200),
            ([1; 32], 201),
        ] {
            assert!(matches!(
                record.remaining_at(boot, time),
                Err(AttemptError::Deadline)
            ));
        }
    }
    #[test]
    fn actual_native_boot_origin_freeze_restore_cannot_extend_admitted_deadline() {
        let original = Instant::now() + Duration::from_secs(30);
        let record = DurableDeadline::freeze(original).unwrap();
        let restored = record
            .restore(Instant::now() + Duration::from_secs(60))
            .unwrap();
        assert!(restored <= original);
        assert!(restored > Instant::now());
        let tighter = Instant::now() + Duration::from_secs(1);
        assert!(record.restore(tighter).unwrap() <= tighter);
    }
}
