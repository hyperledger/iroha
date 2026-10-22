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

/// A process-wide retired-instruction observation for diagnostic workloads.
///
/// The process aggregate includes its worker threads, not just the thread
/// making the call. It also includes concurrent work in the same process and
/// probe-boundary overhead; it is neither elapsed time nor a phone performance
/// qualification. The initial backend supports macOS on AArch64 only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessInstructionSnapshot {
    process_id: u32,
    process_start_abstime: u64,
    instructions: u64,
}

/// An unavailable or inconsistent process instruction measurement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstructionProbeError {
    /// This platform has no supported instruction-counter backend.
    Unsupported,
    /// The operating-system query failed; no numeric sample is available.
    OperatingSystem {
        /// The kernel error number, when supplied by the operating system.
        os_error: Option<i32>,
    },
    /// The kernel observation has a zero process ID or start identity.
    InvalidProcessIdentity,
    /// A zero absolute instruction counter cannot establish availability.
    CounterUnavailable,
    /// The observations belong to different processes or process lifetimes.
    ProcessIdentityChanged,
    /// The later absolute instruction counter is smaller than the earlier one.
    CounterWentBackwards,
    /// The counter did not advance over the requested nonempty work window.
    CounterDidNotAdvance,
}

impl InstructionProbeError {
    /// A stable, whitespace-free diagnostic label, without substituting a count.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Unsupported => "unsupported",
            Self::OperatingSystem { .. } => "operating_system",
            Self::InvalidProcessIdentity => "invalid_process_identity",
            Self::CounterUnavailable => "counter_unavailable",
            Self::ProcessIdentityChanged => "process_identity_changed",
            Self::CounterWentBackwards => "counter_went_backwards",
            Self::CounterDidNotAdvance => "counter_did_not_advance",
        }
    }
}

impl ProcessInstructionSnapshot {
    /// Read this process's cumulative instruction counter without a sampler.
    ///
    /// # Errors
    /// Returns an explicit error for an unsupported backend, a failed kernel
    /// query, an invalid process identity or an unavailable zero counter.
    pub fn capture() -> Result<Self, InstructionProbeError> {
        Self::from_counters(platform::process_instructions())
    }

    fn from_counters(
        counters: Result<platform::ProcessInstructionCounters, platform::InstructionCounterError>,
    ) -> Result<Self, InstructionProbeError> {
        let counters = counters.map_err(|error| match error {
            #[cfg(any(test, not(all(target_os = "macos", target_arch = "aarch64"))))]
            platform::InstructionCounterError::Unsupported => InstructionProbeError::Unsupported,
            #[cfg(any(test, all(target_os = "macos", target_arch = "aarch64")))]
            platform::InstructionCounterError::OperatingSystem(os_error) => {
                InstructionProbeError::OperatingSystem { os_error }
            }
        })?;
        if counters.process_id == 0 || counters.process_start_abstime == 0 {
            return Err(InstructionProbeError::InvalidProcessIdentity);
        }
        if counters.instructions == 0 {
            return Err(InstructionProbeError::CounterUnavailable);
        }
        Ok(Self {
            process_id: counters.process_id,
            process_start_abstime: counters.process_start_abstime,
            instructions: counters.instructions,
        })
    }

    /// Process ID to which this observation belongs.
    pub const fn process_id(self) -> u32 {
        self.process_id
    }

    /// Kernel process-start identity, in absolute-time units rather than seconds.
    pub const fn process_start_abstime(self) -> u64 {
        self.process_start_abstime
    }

    /// Absolute cumulative process instruction count at this observation.
    pub const fn instructions(self) -> u64 {
        self.instructions
    }

    /// Retired instructions in a nonempty work window since `earlier`.
    ///
    /// # Errors
    /// Rejects different process identities, backwards counters and a counter
    /// that did not advance. No unavailable observation becomes a zero delta.
    pub fn instructions_since(self, earlier: Self) -> Result<u64, InstructionProbeError> {
        if self.process_id != earlier.process_id
            || self.process_start_abstime != earlier.process_start_abstime
        {
            return Err(InstructionProbeError::ProcessIdentityChanged);
        }
        let delta = self
            .instructions
            .checked_sub(earlier.instructions)
            .ok_or(InstructionProbeError::CounterWentBackwards)?;
        if delta == 0 {
            return Err(InstructionProbeError::CounterDidNotAdvance);
        }
        Ok(delta)
    }
}

#[cfg(test)]
mod instruction_tests {
    use super::*;

    fn snapshot(
        process_id: u32,
        process_start_abstime: u64,
        instructions: u64,
    ) -> Result<ProcessInstructionSnapshot, InstructionProbeError> {
        ProcessInstructionSnapshot::from_counters(Ok(platform::ProcessInstructionCounters {
            process_id,
            process_start_abstime,
            instructions,
        }))
    }

    #[test]
    fn unavailable_instruction_counters_never_become_zero() {
        assert_eq!(
            ProcessInstructionSnapshot::from_counters(Err(
                platform::InstructionCounterError::Unsupported,
            )),
            Err(InstructionProbeError::Unsupported)
        );
        for os_error in [None, Some(22)] {
            assert_eq!(
                ProcessInstructionSnapshot::from_counters(Err(
                    platform::InstructionCounterError::OperatingSystem(os_error),
                )),
                Err(InstructionProbeError::OperatingSystem { os_error })
            );
        }
        for (pid, start) in [(0, 1), (1, 0), (0, 0)] {
            assert_eq!(
                snapshot(pid, start, 100),
                Err(InstructionProbeError::InvalidProcessIdentity)
            );
        }
        assert_eq!(
            snapshot(7, 9, 0),
            Err(InstructionProbeError::CounterUnavailable)
        );
        let sample = snapshot(7, 9, 100).unwrap();
        assert_eq!(sample.process_id(), 7);
        assert_eq!(sample.process_start_abstime(), 9);
        assert_eq!(sample.instructions(), 100);
    }

    #[test]
    fn instruction_deltas_require_identity_and_positive_monotonic_counts() {
        let before = snapshot(7, 9, 100).unwrap();
        let after = snapshot(7, 9, 150).unwrap();
        assert_eq!(after.instructions_since(before), Ok(50));
        assert_eq!(
            before.instructions_since(after),
            Err(InstructionProbeError::CounterWentBackwards)
        );
        assert_eq!(
            before.instructions_since(before),
            Err(InstructionProbeError::CounterDidNotAdvance)
        );
        for sample in [snapshot(8, 9, 150), snapshot(7, 10, 150)] {
            assert_eq!(
                sample.unwrap().instructions_since(before),
                Err(InstructionProbeError::ProcessIdentityChanged)
            );
        }
        assert_eq!(
            snapshot(7, 9, u64::MAX)
                .unwrap()
                .instructions_since(snapshot(7, 9, u64::MAX - 1).unwrap()),
            Ok(1)
        );
    }

    #[test]
    fn instruction_error_codes_are_stable() {
        for (error, code) in [
            (InstructionProbeError::Unsupported, "unsupported"),
            (
                InstructionProbeError::OperatingSystem { os_error: Some(22) },
                "operating_system",
            ),
            (
                InstructionProbeError::InvalidProcessIdentity,
                "invalid_process_identity",
            ),
            (
                InstructionProbeError::CounterUnavailable,
                "counter_unavailable",
            ),
            (
                InstructionProbeError::ProcessIdentityChanged,
                "process_identity_changed",
            ),
            (
                InstructionProbeError::CounterWentBackwards,
                "counter_went_backwards",
            ),
            (
                InstructionProbeError::CounterDidNotAdvance,
                "counter_did_not_advance",
            ),
        ] {
            assert_eq!(error.code(), code);
            assert!(!error.code().contains(char::is_whitespace));
        }
    }

    #[test]
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    fn unsupported_instruction_backend_is_explicit() {
        assert_eq!(
            ProcessInstructionSnapshot::capture(),
            Err(InstructionProbeError::Unsupported)
        );
    }

    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn process_instruction_probe_observes_worker_work() {
        match ProcessInstructionSnapshot::capture() {
            Ok(_) => {}
            Err(error @ InstructionProbeError::CounterUnavailable) => {
                eprintln!(
                    "PROCESS_INSTRUCTION_WORKER_SANITY status=unavailable error={} worker_work_executed=false",
                    error.code()
                );
                return;
            }
            Err(error) => panic!("instruction probe failed: {error:?}"),
        }
        // Use the same already-started worker and parent rendezvous for an
        // empty control and a work window. The parent waits for completion;
        // only the worker executes the dependent black-boxed arithmetic loop.
        // Requiring work above the control by at least one instruction per
        // iteration is a conservative sanity check, not exact calibration,
        // per-thread attribution or a performance threshold. Start and join
        // are outside both cuts; rendezvous and probe overhead remain inside.
        const ITERATIONS: u32 = 1 << 18;
        let [control_delta, work_delta] = std::thread::scope(|scope| {
            let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(0);
            let (start_tx, start_rx) = std::sync::mpsc::sync_channel(0);
            let (done_tx, done_rx) = std::sync::mpsc::sync_channel(0);
            let worker = scope.spawn(move || {
                ready_tx.send(()).expect("reader receives worker readiness");
                while let Ok(iterations) = start_rx.recv() {
                    let mut value = std::hint::black_box(0x9e37_79b9_7f4a_7c15_u64);
                    for index in 0..iterations {
                        value = std::hint::black_box(
                            value.rotate_left(7).wrapping_add(u64::from(index)),
                        );
                    }
                    if done_tx.send(value).is_err() {
                        break;
                    }
                }
            });
            ready_rx.recv().expect("worker is ready before snapshot");
            let mut deltas = [0; 2];
            for (position, iterations) in [0, ITERATIONS].into_iter().enumerate() {
                let before =
                    ProcessInstructionSnapshot::capture().expect("available before worker");
                start_tx
                    .send(iterations)
                    .expect("release instruction sanity worker");
                std::hint::black_box(done_rx.recv().expect("worker completed"));
                let after = ProcessInstructionSnapshot::capture().expect("available after worker");
                deltas[position] = after
                    .instructions_since(before)
                    .expect("monotonic worker window");
                assert_eq!(before.process_id(), std::process::id());
            }
            // Dropping these channels also releases any parked sender/receiver
            // during caller unwinding; the scoped worker is always joined.
            drop(start_tx);
            drop(done_rx);
            worker.join().expect("instruction sanity worker");
            deltas
        });
        let excess = work_delta
            .checked_sub(control_delta)
            .expect("work exceeds control");
        assert!(
            excess >= u64::from(ITERATIONS),
            "worker instructions missing: control={control_delta} work={work_delta}"
        );
        eprintln!(
            "PROCESS_INSTRUCTION_WORKER_SANITY status=observed control_instructions={control_delta} work_instructions={work_delta} excess_instructions={excess} iterations={ITERATIONS} worker_work_executed=true worker_created_before_cut=true includes_rendezvous=true includes_thread_start_and_join=false"
        );
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
