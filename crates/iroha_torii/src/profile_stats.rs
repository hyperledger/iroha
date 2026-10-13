//! Shared latency summary helpers for opt-in Torii profiling.
use std::time::Duration;
/// Summary of one latency profile run.
#[derive(Clone, Copy, Debug)]
pub struct ProfileSummary {
    /// Number of measured samples.
    pub samples: usize,
    /// Number of warmup samples executed before measurement.
    pub warmup_samples: usize,
    /// Concurrent workers used by the measured run.
    pub concurrency: usize,
    /// End-to-end wall-clock duration for the measured run.
    pub wall_time: Duration,
    /// Average measured sample latency in microseconds.
    pub avg_us: f64,
    /// Median measured sample latency in microseconds.
    pub p50_us: f64,
    /// 95th percentile measured sample latency in microseconds.
    pub p95_us: f64,
    /// 99th percentile measured sample latency in microseconds.
    pub p99_us: f64,
    /// 99.9th percentile measured sample latency when the sample count supports it.
    pub p999_us: Option<f64>,
    /// Maximum measured sample latency in microseconds.
    pub max_us: f64,
    /// Completed operations per second based on wall-clock duration.
    pub throughput_per_sec: f64,
}
/// Convert a duration to microseconds.
#[must_use]
pub fn micros(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000_000.0
}
fn percentile_permille(sorted_samples: &[Duration], permille: usize) -> Duration {
    assert!(!sorted_samples.is_empty());
    let index = (sorted_samples.len() - 1)
        .saturating_mul(permille)
        .saturating_add(500)
        / 1_000;
    sorted_samples[index.min(sorted_samples.len() - 1)]
}
/// Build a latency summary from measured samples.
///
/// `samples` is sorted in place to avoid extra allocation in profiling paths.
#[must_use]
pub fn summarize_profile(
    samples: &mut [Duration],
    warmup_samples: usize,
    concurrency: usize,
    wall_time: Duration,
) -> ProfileSummary {
    assert!(!samples.is_empty());
    samples.sort_unstable();
    let total: f64 = samples.iter().map(std::time::Duration::as_secs_f64).sum();
    let sample_count = samples.len() as f64;
    let wall_secs = wall_time.as_secs_f64();
    ProfileSummary {
        samples: samples.len(),
        warmup_samples,
        concurrency,
        wall_time,
        avg_us: total * 1_000_000.0 / sample_count,
        p50_us: micros(percentile_permille(samples, 500)),
        p95_us: micros(percentile_permille(samples, 950)),
        p99_us: micros(percentile_permille(samples, 990)),
        p999_us: (samples.len() >= 1_000).then(|| micros(percentile_permille(samples, 999))),
        max_us: micros(*samples.last().expect("non-empty samples")),
        throughput_per_sec: if wall_secs > 0.0 {
            sample_count / wall_secs
        } else {
            f64::INFINITY
        },
    }
}
fn p999_label(p999_us: Option<f64>) -> String {
    p999_us.map_or_else(|| "NA".to_owned(), |value| format!("{value:.3}"))
}
/// Print one stable machine-readable Torii profile line.
pub fn print_profile(
    suite: &str,
    kind: &str,
    mut samples: Vec<Duration>,
    warmup_samples: usize,
    concurrency: usize,
    wall_time: Duration,
) {
    let summary = summarize_profile(&mut samples, warmup_samples, concurrency, wall_time);
    eprintln!(
        "torii_profile suite={suite} kind={kind} samples={} warmup_samples={} concurrency={} wall_ms={:.3} throughput_per_sec={:.3} avg_us={:.3} p50_us={:.3} p95_us={:.3} p99_us={:.3} p999_us={} max_us={:.3}",
        summary.samples,
        summary.warmup_samples,
        summary.concurrency,
        summary.wall_time.as_secs_f64() * 1_000.0,
        summary.throughput_per_sec,
        summary.avg_us,
        summary.p50_us,
        summary.p95_us,
        summary.p99_us,
        p999_label(summary.p999_us),
        summary.max_us,
    );
}
#[cfg(test)]
mod tests {
    use super::*;
    fn assert_close(actual: f64, expected: f64) {
        assert!(
            (actual - expected).abs() < f64::EPSILON * 4096.0,
            "expected {expected}, got {actual}"
        );
    }
    #[test]
    fn summary_reports_expected_percentiles_and_throughput() {
        let mut samples = (1..=1_000).map(Duration::from_micros).collect::<Vec<_>>();
        let summary = summarize_profile(&mut samples, 10, 4, Duration::from_secs(2));
        assert_eq!(summary.samples, 1_000);
        assert_eq!(summary.warmup_samples, 10);
        assert_eq!(summary.concurrency, 4);
        assert_close(summary.p50_us, 501.0);
        assert_close(summary.p95_us, 950.0);
        assert_close(summary.p99_us, 990.0);
        assert_close(summary.p999_us.expect("p999 available"), 999.0);
        assert_close(summary.max_us, 1_000.0);
        assert_close(summary.throughput_per_sec, 500.0);
    }
    #[test]
    fn summary_omits_p999_for_small_samples() {
        let mut samples = [Duration::from_micros(1), Duration::from_micros(2)];
        let summary = summarize_profile(&mut samples, 0, 1, Duration::from_millis(1));
        assert_eq!(summary.p999_us, None);
    }
}
