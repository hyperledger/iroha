//! Fallible process probes for benchmark drivers.
//!
//! These observations are for qualification tools, never protocol decisions.
//! Unlike a best-effort recorder, a qualification driver must invalidate a run
//! when its CPU clock or kernel high-water measurement is unavailable.

use crate::{ThermalState, platform};

/// A process-wide resource observation taken directly from the operating system.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessSnapshot {
    /// Process CPU time, including user and system time on every thread.
    pub cpu_ns: u64,
    /// Kernel lifetime high-water resident set, in bytes on every platform.
    ///
    /// This is not a phase-local peak; subtracting two peaks is meaningless.
    pub peak_rss_bytes: u64,
    /// One-minute system load, in thousandths, if the platform exposes it.
    pub load_milli: Option<u64>,
    /// Platform thermal state; unavailable is distinct from nominal.
    pub thermal: ThermalState,
}

/// A missing or inconsistent operating-system measurement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeError {
    /// The process CPU clock could not be read.
    CpuUnavailable,
    /// The kernel high-water resident set could not be read.
    PeakRssUnavailable,
    /// The process CPU clock moved backwards between observations.
    CpuWentBackwards,
}

impl ProcessSnapshot {
    /// Read the CPU clock and kernel lifetime RSS without starting a sampler.
    ///
    /// # Errors
    /// Returns an error if either required operating-system probe is unavailable
    /// or the kernel reports an invalid zero high-water resident set.
    pub fn capture() -> Result<Self, ProbeError> {
        Self::from_probes(
            platform::process_cpu_ns(),
            platform::resource_usage().map(|usage| usage.peak_rss_bytes),
            platform::try_load_average_milli(),
            platform::thermal_state().0,
        )
    }

    fn from_probes(
        cpu_ns: Option<u64>,
        peak_rss_bytes: Option<u64>,
        load_milli: Option<u64>,
        thermal: ThermalState,
    ) -> Result<Self, ProbeError> {
        Ok(Self {
            cpu_ns: cpu_ns.ok_or(ProbeError::CpuUnavailable)?,
            peak_rss_bytes: peak_rss_bytes
                .filter(|bytes| *bytes != 0)
                .ok_or(ProbeError::PeakRssUnavailable)?,
            load_milli,
            thermal,
        })
    }

    /// Process CPU nanoseconds since `earlier`, rejecting a backwards clock.
    ///
    /// # Errors
    /// Returns [`ProbeError::CpuWentBackwards`] if `earlier` has a later CPU time.
    pub fn cpu_since(self, earlier: Self) -> Result<u64, ProbeError> {
        self.cpu_ns
            .checked_sub(earlier.cpu_ns)
            .ok_or(ProbeError::CpuWentBackwards)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_measurements_never_become_zero() {
        let sample =
            |cpu, rss| ProcessSnapshot::from_probes(cpu, rss, None, ThermalState::Unavailable);
        assert_eq!(sample(None, Some(1)), Err(ProbeError::CpuUnavailable));
        assert_eq!(sample(Some(0), None), Err(ProbeError::PeakRssUnavailable));
        assert_eq!(
            sample(Some(0), Some(0)),
            Err(ProbeError::PeakRssUnavailable)
        );
        let value = sample(Some(0), Some(1024)).unwrap();
        assert_eq!(value.cpu_ns, 0);
        assert_eq!(value.peak_rss_bytes, 1024);
        assert_eq!(value.load_milli, None);
        assert_eq!(value.thermal, ThermalState::Unavailable);
    }

    #[test]
    fn backwards_cpu_is_invalid_and_rss_is_not_subtracted() {
        let before =
            ProcessSnapshot::from_probes(Some(100), Some(4096), Some(250), ThermalState::Nominal)
                .unwrap();
        let after = ProcessSnapshot {
            cpu_ns: 150,
            peak_rss_bytes: 8192,
            ..before
        };
        assert_eq!(after.cpu_since(before), Ok(50));
        assert_eq!(before.cpu_since(after), Err(ProbeError::CpuWentBackwards));
        assert_eq!(after.peak_rss_bytes, 8192);
    }

    #[test]
    #[cfg(unix)]
    fn live_kernel_measurements_are_monotonic() {
        let before = ProcessSnapshot::capture().expect("kernel resource probes");
        let after = ProcessSnapshot::capture().expect("kernel resource probes");
        assert!(after.cpu_since(before).is_ok());
        assert!(after.peak_rss_bytes >= before.peak_rss_bytes);
    }
}
