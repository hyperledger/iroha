//! Process-local E1 elapsed readings; never a custody boot identity or persisted time anchor.

use iroha_primitives::time::NativeContinuousReading;

use super::{KagemushaWalletPlatformV1, KagemushaWalletUnavailableV1};

/// Genuine process-bound, suspend-inclusive reading. It is never serialized or restored.
#[cfg(not(test))]
pub type LiveEnrollmentReadingV1 = NativeContinuousReading;

/// Test-only reading injection; production uses the native type directly.
#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub enum LiveEnrollmentReadingV1 {
    Native(NativeContinuousReading),
    Simulated { domain: [u8; 32], nanos: u128 },
}

#[cfg(test)]
impl LiveEnrollmentReadingV1 {
    pub(crate) fn elapsed_since(&self, earlier: &Self) -> std::io::Result<std::time::Duration> {
        let invalid = || std::io::Error::other("live enrollment clock domain changed or regressed");
        match (self, earlier) {
            (Self::Native(now), Self::Native(started)) => now.elapsed_since(started),
            (
                Self::Simulated { domain, nanos },
                Self::Simulated {
                    domain: earlier_domain,
                    nanos: earlier_nanos,
                },
            ) if *domain != [0; 32] && domain == earlier_domain => {
                let elapsed = nanos.checked_sub(*earlier_nanos).ok_or_else(invalid)?;
                Ok(std::time::Duration::new(
                    u64::try_from(elapsed / 1_000_000_000).map_err(|_| invalid())?,
                    (elapsed % 1_000_000_000) as u32,
                ))
            }
            _ => Err(invalid()),
        }
    }
}

pub(super) fn read<P: KagemushaWalletPlatformV1>(
    platform: &P,
) -> Result<LiveEnrollmentReadingV1, KagemushaWalletUnavailableV1> {
    #[cfg(not(test))]
    let _ = platform;
    #[cfg(test)]
    if let Some(reading) = platform.live_enrollment_clock_for_test() {
        let (domain, nanos) = reading?;
        return Ok(LiveEnrollmentReadingV1::Simulated { domain, nanos });
    }
    let reading = NativeContinuousReading::now()
        .map_err(|error| KagemushaWalletUnavailableV1::from_io(&error))?;
    #[cfg(test)]
    return Ok(LiveEnrollmentReadingV1::Native(reading));
    #[cfg(not(test))]
    Ok(reading)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simulated_domains_refuse_mixing_regression_and_duration_overflow() {
        let start = LiveEnrollmentReadingV1::Simulated {
            domain: [1; 32],
            nanos: 10,
        };
        let native = LiveEnrollmentReadingV1::Native(NativeContinuousReading::now().unwrap());
        assert!(start.elapsed_since(&native).is_err());
        assert!(native.elapsed_since(&start).is_err());
        for (domain, nanos) in [
            ([2; 32], 11),
            ([0; 32], 11),
            ([1; 32], 9),
            ([1; 32], u128::MAX),
        ] {
            let now = LiveEnrollmentReadingV1::Simulated { domain, nanos };
            assert!(now.elapsed_since(&start).is_err());
        }
        let now = LiveEnrollmentReadingV1::Simulated {
            domain: [1; 32],
            nanos: 120_000_000_731,
        };
        assert_eq!(
            now.elapsed_since(&start).unwrap(),
            std::time::Duration::new(120, 721)
        );
    }
}
