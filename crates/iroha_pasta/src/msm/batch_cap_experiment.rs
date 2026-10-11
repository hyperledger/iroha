//! Explicit ignored batch-cap experiment; not a proof or performance qualification.
//!
//! Each invocation selects one fixed public divisor before creating its worker pool.
//! The production planner/reservation and every secret arithmetic path stay unchanged.
//! Direct per-process CPU/RSS accounting is recorded by the external diagnostic runner.

use super::*;
use crate::{
    Ep, Eq,
    msm::{MemoryBudget, SharedMemoryBudget, msm_secret_with_shared_budget},
};
use group::{GroupEncoding, prime::PrimeCurveAffine};
use rand_chacha::{
    ChaCha20Rng,
    rand_core::{RngCore, SeedableRng},
};
use sha2::{Digest, Sha256};
use std::{
    sync::atomic::{AtomicUsize, Ordering},
    time::Instant,
};

static DIVISOR: AtomicUsize = AtomicUsize::new(4);

pub(super) fn cap(count: usize, production: usize) -> usize {
    let divisor = DIVISOR.load(Ordering::Relaxed);
    assert!(matches!(divisor, 4 | 8 | 16));
    let selected = (count / divisor).clamp(16, MAX_BATCH);
    assert!(selected <= production);
    selected
}
struct Reset;
impl Drop for Reset {
    fn drop(&mut self) {
        DIVISOR.store(4, Ordering::Relaxed);
    }
}
fn number(name: &str) -> usize {
    std::env::var(name)
        .expect("explicit experimental input")
        .parse()
        .expect("decimal experimental input")
}
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    out
}
fn run<C: PastaCurve>(curve: &str, divisor: usize, workers: usize, n: usize, sparse: bool) {
    let setup = Instant::now();
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(workers)
        .build()
        .unwrap();
    let mut rng = ChaCha20Rng::seed_from_u64(0x6274_6361_7031);
    let mut scalars: Vec<C::ScalarExt> = (0..n)
        .map(|index| {
            if !sparse || index >= n - 5 {
                C::ScalarExt::random(&mut rng)
            } else if index % 8 == 0 {
                C::ScalarExt::from(u64::from(rng.next_u32() & 65535))
            } else {
                C::ScalarExt::ZERO
            }
        })
        .collect();
    let mut points = Vec::with_capacity(n);
    let mut point = C::identity();
    let mut expected_scalar = C::ScalarExt::ZERO;
    for (index, scalar) in scalars.iter().enumerate() {
        point += C::generator();
        points.push(point);
        expected_scalar += *scalar * C::ScalarExt::from((index + 1) as u64);
    }
    // Independent integer-weight relation, rather than another Pippenger invocation.
    let expected = C::generator() * expected_scalar;
    let mut bases = vec![C::AffineExt::identity(); n];
    C::batch_normalize(&points, &mut bases);
    drop(points);
    let plan = plan(n, 255, workers, MemoryBudget::DEFAULT.bytes()).unwrap();
    let shared = SharedMemoryBudget::new(64 << 20);
    let setup_ns = setup.elapsed().as_nanos();
    let mut samples = Vec::new();
    pool.install(|| {
        assert_eq!(rayon::current_num_threads(), workers);
        for _ in 0..3 {
            let start = Instant::now();
            let actual = msm_secret_with_shared_budget::<C>(
                &scalars,
                &bases,
                MemoryBudget::DEFAULT,
                &shared,
            )
            .unwrap();
            samples.push(start.elapsed().as_nanos());
            assert_eq!(actual, expected);
            assert_eq!(shared.in_use_bytes(), 0);
        }
    });
    assert_eq!(shared.peak_bytes(), plan.bytes);
    assert!(shared.peak_bytes() <= 64 << 20);
    let result = expected.to_affine().to_bytes();
    println!(
        "MSM_BATCH_DIAGNOSTIC curve={curve} divisor={divisor} workers={workers} n={n} sparse_blinded={sparse} setup_ns={setup_ns} samples_ns={samples:?} planned_scratch={} reserved_peak={} result_sha256={} window={} windows={} windows_per_task={} chunks={} concurrency={} scope=experimental_only",
        plan.bytes,
        shared.peak_bytes(),
        hex(&Sha256::digest(result.as_ref())),
        plan.c,
        plan.nw,
        plan.per_group,
        plan.chunks,
        plan.concurrency
    );
    scalars.iter_mut().zeroize();
}

#[test]
#[ignore = "explicit fresh-process batch-cap sweep; no production configuration or qualification claim"]
fn batch_cap_diagnostic() {
    let divisor = number("KAGEMUSHA_MSM_BATCH_DIVISOR");
    let workers = number("KAGEMUSHA_MSM_BATCH_WORKERS");
    let n = number("KAGEMUSHA_MSM_BATCH_N");
    let curve = std::env::var("KAGEMUSHA_MSM_BATCH_CURVE").unwrap();
    let shape = std::env::var("KAGEMUSHA_MSM_BATCH_SHAPE").unwrap();
    assert!(matches!(divisor, 4 | 8 | 16));
    assert!(matches!(workers, 1 | 4));
    assert!(matches!(n, 4096 | 16384 | 65536));
    assert!(matches!(shape.as_str(), "full_width" | "sparse_blinded"));
    let _reset = Reset;
    DIVISOR.store(divisor, Ordering::Relaxed);
    match curve.as_str() {
        "pallas" => run::<Ep>(&curve, divisor, workers, n, shape == "sparse_blinded"),
        "vesta" => run::<Eq>(&curve, divisor, workers, n, shape == "sparse_blinded"),
        _ => panic!("explicit supported curve"),
    }
}

#[test]
fn diagnostic_batch_caps_never_exceed_production_reservation() {
    // No global mutation in the ordinary suite.
    for count in [1, 16, 64, 256, 1024, 4096, 65536] {
        let production = (count / 4).clamp(16, MAX_BATCH);
        for divisor in [4, 8, 16] {
            assert!((count / divisor).clamp(16, MAX_BATCH) <= production);
        }
        assert!(cap(count, production) <= production);
    }
}
