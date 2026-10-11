//! Operating-system probes: CPU clocks, peak RSS, the enforced address-space
//! limit, system load and thermal state.
//!
//! Every probe is read-only and returns `None` (or an explicit unavailable
//! word) where the platform does not expose the fact. Nothing here changes a
//! limit, a clock or any process state.

#[cfg(any(test, target_os = "linux", target_os = "android"))]
use std::path::Path;

use crate::schema::ThermalState;

/// Process CPU time and the kernel's lifetime peak resident set size.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ResourceUsage {
    pub user_ns: u64,
    pub system_ns: u64,
    pub peak_rss_bytes: u64,
}

/// The `RLIMIT_AS` pair; `None` means unlimited.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AddressSpaceLimit {
    pub soft_bytes: Option<u64>,
    pub hard_bytes: Option<u64>,
}

/// Public label of the interface that reports the address-space limit.
pub const ADDRESS_SPACE_SOURCE: &str = if cfg!(unix) {
    "getrlimit.RLIMIT_AS"
} else {
    "unavailable"
};

/// Convert seconds and a sub-second part into nanoseconds without wrapping.
pub fn nanoseconds(seconds: u64, fraction: u64, fraction_per_second: u64) -> u64 {
    let scale = 1_000_000_000 / fraction_per_second.max(1);
    seconds
        .saturating_mul(1_000_000_000)
        .saturating_add(fraction.saturating_mul(scale))
}

/// Convert a raw resource limit, where `infinity` means unlimited.
pub fn finite_limit(raw: u64, infinity: u64) -> Option<u64> {
    (raw != infinity).then_some(raw)
}

/// Scale `ru_maxrss` to bytes: kilobytes on Linux, bytes on Apple platforms.
pub fn peak_rss_bytes(raw: u64, reported_in_kilobytes: bool) -> u64 {
    if reported_in_kilobytes {
        raw.saturating_mul(1024)
    } else {
        raw
    }
}

/// Convert a load average to an exact integer in thousandths.
pub fn load_to_milli(load: f64) -> Option<u64> {
    if !load.is_finite() || load < 0.0 {
        return None;
    }
    let scaled = (load * 1000.0).round();
    // Loads are far below 2^53, so the conversion is exact.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    (scaled < 9.0e15).then_some(scaled as u64)
}

/// Convert the kernel's `sysinfo` load, a fixed-point number with 16
/// fractional bits, to a load average.
#[cfg(any(test, target_os = "android"))]
pub fn fixed_point_load(raw: u64) -> f64 {
    // Loads are far below 2^37, so both conversions are exact.
    #[allow(clippy::cast_precision_loss)]
    let scaled = raw as f64;
    scaled / 65_536.0
}

/// Map the macOS thermal pressure level to the schema's thermal state.
///
/// macOS numbers the levels consecutively: nominal, moderate, heavy, then
/// trapping and sleeping.
pub fn darwin_pressure_state(level: u64) -> ThermalState {
    match level {
        0 => ThermalState::Nominal,
        1 => ThermalState::Fair,
        2 => ThermalState::Serious,
        _ => ThermalState::Critical,
    }
}

/// Map the iOS thermal pressure level to the schema's thermal state.
///
/// The same notification carries a different scale on iOS: nominal 0, light
/// 10, moderate 20, heavy 30, then trapping 40 and sleeping 50. Light and
/// moderate pressure are `fair`, heavy is `serious`, and anything at or above
/// trapping is `critical`.
#[cfg(any(test, target_os = "ios"))]
pub fn ios_pressure_state(level: u64) -> ThermalState {
    match level {
        0..=9 => ThermalState::Nominal,
        10..=29 => ThermalState::Fair,
        30..=39 => ThermalState::Serious,
        _ => ThermalState::Critical,
    }
}

#[cfg(any(test, target_os = "linux", target_os = "android"))]
fn read_millidegrees(path: &Path) -> Option<i64> {
    let text = std::fs::read_to_string(path).ok()?;
    text.trim().parse().ok()
}

/// Derive a thermal state from a Linux `thermal` sysfs class directory.
///
/// Each `thermal_zone*` contributes its temperature against its own
/// `passive`, `hot` and `critical` trip points; the most severe zone wins.
/// Zones without a readable temperature are ignored, and a directory with no
/// readable zone is unavailable.
///
/// Android exposes the same class directory, but its sandbox usually denies
/// applications the read. The probe then reports unavailable, and a device
/// run must take its thermal state from the SDK emitter instead.
#[cfg(any(test, target_os = "linux", target_os = "android"))]
pub fn linux_thermal_state_from(directory: &Path) -> ThermalState {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return ThermalState::Unavailable;
    };
    let mut worst: Option<u8> = None;
    for entry in entries.flatten() {
        let name = entry.file_name();
        if !name.to_string_lossy().starts_with("thermal_zone") {
            continue;
        }
        let zone = entry.path();
        let Some(temperature) = read_millidegrees(&zone.join("temp")) else {
            continue;
        };
        let mut severity = 0_u8;
        for trip in 0..16 {
            let Ok(kind) = std::fs::read_to_string(zone.join(format!("trip_point_{trip}_type")))
            else {
                break;
            };
            let Some(threshold) = read_millidegrees(&zone.join(format!("trip_point_{trip}_temp")))
            else {
                continue;
            };
            if temperature < threshold {
                continue;
            }
            severity = severity.max(match kind.trim() {
                "critical" => 3,
                "hot" => 2,
                "passive" | "active" => 1,
                _ => 0,
            });
        }
        worst = Some(worst.map_or(severity, |current| current.max(severity)));
    }
    match worst {
        None => ThermalState::Unavailable,
        Some(0) => ThermalState::Nominal,
        Some(1) => ThermalState::Fair,
        Some(2) => ThermalState::Serious,
        Some(_) => ThermalState::Critical,
    }
}

/// Logical processors available to this process; zero when unknown.
pub fn logical_cpus() -> u32 {
    std::thread::available_parallelism()
        .ok()
        .and_then(|count| u32::try_from(count.get()).ok())
        .unwrap_or(0)
}

#[cfg(unix)]
#[allow(unsafe_code)]
mod unix {
    use super::{AddressSpaceLimit, ResourceUsage, finite_limit, nanoseconds, peak_rss_bytes};

    fn clock_ns(clock: libc::clockid_t) -> Option<u64> {
        let mut time = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: `time` is a valid, exclusively borrowed timespec and the
        // call writes nothing else.
        let status = unsafe { libc::clock_gettime(clock, &raw mut time) };
        if status != 0 {
            return None;
        }
        Some(nanoseconds(
            u64::try_from(time.tv_sec).ok()?,
            u64::try_from(time.tv_nsec).ok()?,
            1_000_000_000,
        ))
    }

    pub fn thread_cpu_ns() -> Option<u64> {
        clock_ns(libc::CLOCK_THREAD_CPUTIME_ID)
    }

    pub fn process_cpu_ns() -> Option<u64> {
        clock_ns(libc::CLOCK_PROCESS_CPUTIME_ID)
    }

    pub fn resource_usage() -> Option<ResourceUsage> {
        // SAFETY: an all-zero `rusage` is a valid value of this plain C struct.
        let mut usage: libc::rusage = unsafe { core::mem::zeroed() };
        // SAFETY: `usage` is a valid, exclusively borrowed rusage.
        let status = unsafe { libc::getrusage(libc::RUSAGE_SELF, &raw mut usage) };
        if status != 0 {
            return None;
        }
        let time = |value: libc::timeval| {
            Some(nanoseconds(
                u64::try_from(value.tv_sec).ok()?,
                u64::try_from(value.tv_usec).ok()?,
                1_000_000,
            ))
        };
        Some(ResourceUsage {
            user_ns: time(usage.ru_utime)?,
            system_ns: time(usage.ru_stime)?,
            peak_rss_bytes: peak_rss_bytes(
                u64::try_from(usage.ru_maxrss).ok()?,
                !cfg!(target_vendor = "apple"),
            ),
        })
    }

    pub fn address_space_limit() -> Option<AddressSpaceLimit> {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `limit` is a valid, exclusively borrowed rlimit.
        let status = unsafe { libc::getrlimit(libc::RLIMIT_AS, &raw mut limit) };
        if status != 0 {
            return None;
        }
        #[allow(clippy::useless_conversion)]
        let (soft, hard, infinity) = (
            u64::from(limit.rlim_cur),
            u64::from(limit.rlim_max),
            u64::from(libc::RLIM_INFINITY),
        );
        Some(AddressSpaceLimit {
            soft_bytes: finite_limit(soft, infinity),
            hard_bytes: finite_limit(hard, infinity),
        })
    }

    #[cfg(not(target_os = "android"))]
    pub fn load_average() -> Option<f64> {
        let mut loads = [0.0_f64; 1];
        // SAFETY: the buffer holds exactly the one element requested.
        let written = unsafe { libc::getloadavg(loads.as_mut_ptr(), 1) };
        (written == 1).then_some(loads[0])
    }

    /// Android's C library has no `getloadavg` binding; the kernel reports
    /// the same one-minute load through `sysinfo` as a 16-bit fixed-point
    /// number.
    #[cfg(target_os = "android")]
    pub fn load_average() -> Option<f64> {
        // SAFETY: an all-zero `sysinfo` is a valid value of this plain C struct.
        let mut info: libc::sysinfo = unsafe { core::mem::zeroed() };
        // SAFETY: `info` is a valid, exclusively borrowed sysinfo.
        let status = unsafe { libc::sysinfo(&raw mut info) };
        (status == 0).then(|| super::fixed_point_load(u64::from(info.loads[0])))
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
#[allow(unsafe_code)]
mod darwin_thermal {
    use core::ffi::{c_char, c_int};

    // libSystem's notify(3) interface; the thermal pressure level is a public
    // system notification state readable without entitlements.
    unsafe extern "C" {
        fn notify_register_check(name: *const c_char, out_token: *mut c_int) -> u32;
        fn notify_get_state(token: c_int, state: *mut u64) -> u32;
        fn notify_cancel(token: c_int) -> u32;
    }

    pub fn pressure_level() -> Option<u64> {
        let name = c"com.apple.system.thermalpressurelevel";
        let mut token: c_int = 0;
        // SAFETY: `name` is a valid NUL-terminated string and `token` is a
        // valid, exclusively borrowed integer.
        if unsafe { notify_register_check(name.as_ptr(), &raw mut token) } != 0 {
            return None;
        }
        let mut level = 0_u64;
        // SAFETY: `token` was just registered and `level` is exclusively borrowed.
        let status = unsafe { notify_get_state(token, &raw mut level) };
        // SAFETY: `token` was registered above and is cancelled exactly once.
        let _ = unsafe { notify_cancel(token) };
        (status == 0).then_some(level)
    }
}

/// CPU time consumed by the calling thread.
pub fn thread_cpu_ns() -> Option<u64> {
    #[cfg(unix)]
    {
        unix::thread_cpu_ns()
    }
    #[cfg(not(unix))]
    {
        None
    }
}

/// CPU time consumed by the whole process.
pub fn process_cpu_ns() -> Option<u64> {
    #[cfg(unix)]
    {
        unix::process_cpu_ns()
    }
    #[cfg(not(unix))]
    {
        None
    }
}

/// Process CPU split and lifetime peak RSS from the kernel.
pub fn resource_usage() -> Option<ResourceUsage> {
    #[cfg(unix)]
    {
        unix::resource_usage()
    }
    #[cfg(not(unix))]
    {
        None
    }
}

/// The address-space limit currently in force for this process.
pub fn address_space_limit() -> Option<AddressSpaceLimit> {
    #[cfg(unix)]
    {
        unix::address_space_limit()
    }
    #[cfg(not(unix))]
    {
        None
    }
}

/// One-minute system load in thousandths; zero when unavailable.
pub fn load_average_milli() -> u64 {
    try_load_average_milli().unwrap_or(0)
}

/// One-minute system load in thousandths, preserving probe unavailability.
pub fn try_load_average_milli() -> Option<u64> {
    #[cfg(unix)]
    {
        unix::load_average().and_then(load_to_milli)
    }
    #[cfg(not(unix))]
    {
        None
    }
}

/// Thermal state and the public label of the interface that supplied it.
pub fn thermal_state() -> (ThermalState, &'static str) {
    #[cfg(target_os = "macos")]
    {
        darwin_thermal::pressure_level().map_or(
            (ThermalState::Unavailable, "unavailable"),
            |level| {
                (
                    darwin_pressure_state(level),
                    "darwin.notify.thermalpressurelevel",
                )
            },
        )
    }
    #[cfg(target_os = "ios")]
    {
        // TODO: this probe is compile-checked for iOS but has not run on a
        // device; the first device run of a consumer task must confirm it.
        darwin_thermal::pressure_level().map_or(
            (ThermalState::Unavailable, "unavailable"),
            |level| {
                (
                    ios_pressure_state(level),
                    "darwin.notify.thermalpressurelevel",
                )
            },
        )
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        // TODO: the Android branch is compile-checked only and has not run on
        // a device; an application is usually denied this read, and a device
        // run then takes its thermal state from the SDK emitter.
        match linux_thermal_state_from(Path::new("/sys/class/thermal")) {
            ThermalState::Unavailable => (ThermalState::Unavailable, "unavailable"),
            state => (state, "linux.sysfs.thermal_zone"),
        }
    }
    #[cfg(not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "linux",
        target_os = "android"
    )))]
    {
        (ThermalState::Unavailable, "unavailable")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nanosecond_conversion_is_exact_and_saturates() {
        assert_eq!(nanoseconds(0, 0, 1_000_000_000), 0);
        assert_eq!(nanoseconds(2, 5, 1_000_000_000), 2_000_000_005);
        assert_eq!(nanoseconds(3, 7, 1_000_000), 3_000_007_000);
        assert_eq!(nanoseconds(u64::MAX, 1, 1_000_000), u64::MAX);
        assert_eq!(nanoseconds(1, 1, 0), 2_000_000_000);
    }

    #[test]
    fn infinite_limit_is_reported_as_unlimited() {
        assert_eq!(finite_limit(u64::MAX, u64::MAX), None);
        assert_eq!(finite_limit(32 << 30, u64::MAX), Some(32 << 30));
        assert_eq!(finite_limit(0, u64::MAX), Some(0));
    }

    #[test]
    fn peak_rss_scaling_follows_the_platform_unit() {
        assert_eq!(peak_rss_bytes(2048, true), 2048 * 1024);
        assert_eq!(peak_rss_bytes(2048, false), 2048);
        assert_eq!(peak_rss_bytes(u64::MAX, true), u64::MAX);
    }

    #[test]
    fn load_is_converted_to_exact_thousandths() {
        assert_eq!(load_to_milli(0.0), Some(0));
        assert_eq!(load_to_milli(2.756), Some(2756));
        assert_eq!(load_to_milli(19.9996), Some(20_000));
        assert_eq!(load_to_milli(-1.0), None);
        assert_eq!(load_to_milli(f64::NAN), None);
        assert_eq!(load_to_milli(f64::INFINITY), None);
        assert_eq!(load_to_milli(1.0e16), None);
    }

    #[test]
    fn kernel_fixed_point_load_is_scaled_by_two_to_the_sixteenth() {
        assert_eq!(load_to_milli(fixed_point_load(0)), Some(0));
        assert_eq!(load_to_milli(fixed_point_load(65_536)), Some(1000));
        assert_eq!(load_to_milli(fixed_point_load(98_304)), Some(1500));
        assert_eq!(load_to_milli(fixed_point_load(180_618)), Some(2756));
    }

    #[test]
    fn darwin_pressure_levels_map_to_states() {
        assert_eq!(darwin_pressure_state(0), ThermalState::Nominal);
        assert_eq!(darwin_pressure_state(1), ThermalState::Fair);
        assert_eq!(darwin_pressure_state(2), ThermalState::Serious);
        assert_eq!(darwin_pressure_state(3), ThermalState::Critical);
        assert_eq!(darwin_pressure_state(4), ThermalState::Critical);
    }

    #[test]
    fn ios_pressure_levels_use_the_device_scale() {
        for (level, state) in [
            (0, ThermalState::Nominal),
            (9, ThermalState::Nominal),
            (10, ThermalState::Fair),
            (20, ThermalState::Fair),
            (29, ThermalState::Fair),
            (30, ThermalState::Serious),
            (39, ThermalState::Serious),
            (40, ThermalState::Critical),
            (50, ThermalState::Critical),
            (u64::MAX, ThermalState::Critical),
        ] {
            assert_eq!(ios_pressure_state(level), state, "{level}");
        }
        // The desktop scale would misread every device level above nominal.
        assert_eq!(darwin_pressure_state(10), ThermalState::Critical);
    }

    fn zone(root: &Path, name: &str, temperature: &str, trips: &[(&str, &str)]) {
        let directory = root.join(name);
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join("temp"), temperature).unwrap();
        for (index, (kind, threshold)) in trips.iter().enumerate() {
            std::fs::write(directory.join(format!("trip_point_{index}_type")), kind).unwrap();
            std::fs::write(
                directory.join(format!("trip_point_{index}_temp")),
                threshold,
            )
            .unwrap();
        }
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "iroha-measurement-thermal-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        directory
    }

    #[test]
    fn linux_thermal_state_uses_the_most_severe_zone() {
        let root = scratch("severity");
        assert_eq!(linux_thermal_state_from(&root), ThermalState::Unavailable);
        zone(
            &root,
            "thermal_zone0",
            "45000\n",
            &[("passive", "80000"), ("critical", "100000")],
        );
        assert_eq!(linux_thermal_state_from(&root), ThermalState::Nominal);
        zone(
            &root,
            "thermal_zone1",
            "85000\n",
            &[("passive", "80000"), ("hot", "95000")],
        );
        assert_eq!(linux_thermal_state_from(&root), ThermalState::Fair);
        zone(
            &root,
            "thermal_zone2",
            "96000\n",
            &[("passive", "80000"), ("hot", "95000")],
        );
        assert_eq!(linux_thermal_state_from(&root), ThermalState::Serious);
        zone(
            &root,
            "thermal_zone3",
            "101000\n",
            &[("critical", "100000")],
        );
        assert_eq!(linux_thermal_state_from(&root), ThermalState::Critical);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn linux_thermal_state_ignores_unreadable_zones_and_other_entries() {
        let root = scratch("unreadable");
        zone(&root, "cooling_device0", "99999999", &[("critical", "1")]);
        std::fs::create_dir_all(root.join("thermal_zone0")).unwrap();
        zone(&root, "thermal_zone1", "not-a-number", &[("critical", "1")]);
        assert_eq!(linux_thermal_state_from(&root), ThermalState::Unavailable);
        zone(&root, "thermal_zone2", "30000", &[("unknown", "1")]);
        assert_eq!(linux_thermal_state_from(&root), ThermalState::Nominal);
        assert_eq!(
            linux_thermal_state_from(&root.join("absent")),
            ThermalState::Unavailable
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn logical_cpu_count_is_positive_on_supported_hosts() {
        assert!(logical_cpus() >= 1);
    }

    #[cfg(unix)]
    #[test]
    fn cpu_clocks_advance_with_work_and_never_go_backwards() {
        let thread_before = thread_cpu_ns().unwrap();
        let process_before = process_cpu_ns().unwrap();
        let mut accumulator = 0_u64;
        for value in 0..4_000_000_u64 {
            accumulator = accumulator.wrapping_mul(31).wrapping_add(value);
        }
        std::hint::black_box(accumulator);
        let thread_after = thread_cpu_ns().unwrap();
        let process_after = process_cpu_ns().unwrap();
        assert!(thread_after > thread_before);
        assert!(process_after >= process_before);
        assert!(process_after - process_before > 0);
    }

    #[cfg(unix)]
    #[test]
    fn resource_usage_reports_a_positive_peak_and_monotonic_cpu() {
        let first = resource_usage().unwrap();
        assert!(first.peak_rss_bytes > 1024 * 1024, "{first:?}");
        let mut accumulator = 0_u64;
        for value in 0..2_000_000_u64 {
            accumulator = accumulator.wrapping_add(value * value);
        }
        std::hint::black_box(accumulator);
        let second = resource_usage().unwrap();
        assert!(second.user_ns >= first.user_ns);
        assert!(second.system_ns >= first.system_ns);
        assert!(second.peak_rss_bytes >= first.peak_rss_bytes);
    }

    #[cfg(unix)]
    #[test]
    fn address_space_limit_matches_the_kernel_and_orders_soft_below_hard() {
        let limit = address_space_limit().unwrap();
        if let (Some(soft), Some(hard)) = (limit.soft_bytes, limit.hard_bytes) {
            assert!(soft <= hard);
        }
        if limit.hard_bytes.is_some() {
            // A finite hard limit bounds the soft limit; an unlimited soft
            // limit under a finite hard limit is impossible.
            assert!(limit.soft_bytes.is_some());
        }
        assert_eq!(address_space_limit().unwrap(), limit);
        assert_eq!(ADDRESS_SPACE_SOURCE, "getrlimit.RLIMIT_AS");
    }

    #[cfg(unix)]
    #[test]
    fn load_average_is_available_as_thousandths() {
        // A real host reports a small non-negative load; the probe must not
        // fall back to zero because of a conversion failure.
        let load = load_average_milli();
        assert!(load < 100_000_000, "{load}");
    }

    #[test]
    fn thermal_probe_names_its_source_or_reports_unavailable() {
        let (state, source) = thermal_state();
        assert!(crate::text::is_public_label(source));
        assert_eq!(state == ThermalState::Unavailable, source == "unavailable");
        #[cfg(target_os = "macos")]
        assert_eq!(source, "darwin.notify.thermalpressurelevel");
    }
}
