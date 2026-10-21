//! Resource-accounting regressions, registered only by the Load integration target.

use crate::load_chain::native_load_measurement::{
    Metrics, ObservationError, Sample, metrics, parse_workers, validate_samples, worker_census,
};
use iroha_measurement::{
    ThermalState,
    probe::{ProbeError, ProcessSnapshot},
};

fn snapshot(cpu_ns: u64, peak_rss_bytes: u64) -> ProcessSnapshot {
    ProcessSnapshot {
        cpu_ns,
        peak_rss_bytes,
        load_milli: None,
        thermal: ThermalState::Unavailable,
    }
}

fn sample(index: usize, cpu_ns: u64, elapsed_ns: u64) -> Sample {
    Sample {
        index,
        identity_sha256: "fixed-input-and-key".into(),
        proof_sha256: format!("{index:064x}"),
        proof_bytes: 100,
        frame_words: 69,
        native_terminal_accepted: true,
        terminal: Metrics {
            before: snapshot(100, 4096),
            after: snapshot(100 + cpu_ns, 8192),
            cpu_ns,
            elapsed_ns,
        },
        scratch_retained_bytes: 0,
        output: norito::json!({}),
    }
}

#[test]
fn worker_parser_rejects_absent_unsupported_and_malformed() {
    assert_eq!(parse_workers(Some("1")), Ok(1));
    assert_eq!(parse_workers(Some("4")), Ok(4));
    for value in [
        None,
        Some("0"),
        Some("2"),
        Some("8"),
        Some("01"),
        Some(" 1"),
        Some("four"),
    ] {
        assert!(parse_workers(value).is_err(), "{value:?}");
    }
}

#[test]
fn worker_census_matches_requested_pool() {
    for workers in [1, 4] {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .build()
            .unwrap();
        assert_eq!(
            worker_census(&pool, workers),
            (0..workers).collect::<Vec<_>>()
        );
    }
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .unwrap();
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| worker_census(&pool, 4))).is_err()
    );
}

#[test]
fn phase_accounting_rejects_probe_failure_and_backwards_cpu() {
    let good = Ok(snapshot(100, 4096));
    for error in [ProbeError::CpuUnavailable, ProbeError::PeakRssUnavailable] {
        assert_eq!(
            metrics(Err(error), good, 1),
            Err(ObservationError::Probe(error))
        );
        assert_eq!(
            metrics(good, Err(error), 1),
            Err(ObservationError::Probe(error))
        );
    }
    assert_eq!(
        metrics(good, Ok(snapshot(99, 8192)), 1),
        Err(ObservationError::Probe(ProbeError::CpuWentBackwards))
    );
    assert_eq!(
        metrics(good, Ok(snapshot(101, 2048)), 1),
        Err(ObservationError::RssWentBackwards)
    );
}

#[test]
fn phase_accounting_preserves_absolute_peak_rss() {
    let observed = metrics(Ok(snapshot(100, 4096)), Ok(snapshot(150, 16384)), 80).unwrap();
    assert_eq!(observed.cpu_ns, 50);
    assert_eq!(observed.elapsed_ns, 80);
    assert_eq!(observed.after.peak_rss_bytes, 16384);
    assert_eq!(observed.before.peak_rss_bytes, 4096);
    assert_eq!(observed.after.thermal, ThermalState::Unavailable);
    for (before, after) in [(0, 8192), (4096, 0)] {
        assert_eq!(
            metrics(Ok(snapshot(1, before)), Ok(snapshot(2, after)), 1),
            Err(ObservationError::Probe(ProbeError::PeakRssUnavailable))
        );
    }
}

#[test]
fn record_requires_two_fresh_verified_samples() {
    let identity = "fixed-input-and-key";
    let valid = vec![sample(0, 20, 30), sample(1, 25, 40)];
    assert!(validate_samples(&valid, identity).is_ok());
    assert!(validate_samples(&[], identity).is_err());
    assert!(validate_samples(&valid[..1], identity).is_err());
    let mut excess = valid.clone();
    excess.push(sample(2, 1, 1));
    assert!(validate_samples(&excess, identity).is_err());
    for mutation in 0..9 {
        let mut bad = valid.clone();
        match mutation {
            0 => bad[1].index = 0,
            1 => bad[1].proof_sha256.clone_from(&valid[0].proof_sha256),
            2 => bad[1].native_terminal_accepted = false,
            3 => bad[1].identity_sha256 = "foreign-fixture-or-key".into(),
            4 => bad[1].scratch_retained_bytes = 1,
            5 => bad[1].proof_bytes = 0,
            6 => bad[1].frame_words = 68,
            7 => bad[1].terminal.cpu_ns = 0,
            _ => bad[1].terminal.elapsed_ns = 0,
        }
        assert!(
            validate_samples(&bad, identity).is_err(),
            "mutation {mutation}"
        );
    }
}

#[test]
fn slower_cpu_and_elapsed_are_selected_independently() {
    let samples = vec![sample(0, 30, 40), sample(1, 20, 50)];
    assert_eq!(
        validate_samples(&samples, "fixed-input-and-key"),
        Ok((0, 1))
    );
    let tied = vec![sample(0, 20, 40), sample(1, 20, 40)];
    assert_eq!(validate_samples(&tied, "fixed-input-and-key"), Ok((0, 0)));
}
