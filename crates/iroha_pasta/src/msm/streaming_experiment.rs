//! Fresh-process forced-contention comparison, separate from proof qualification.
//!
//! The stack mode executes the prior fallback directly. Both modes keep the same
//! artificial reservation alive and verify the output against an independent
//! single-scalar relation. Reservation bytes are not physical RSS. An external
//! runner must retain process CPU/RSS, binary/source identity and host probes.

use super::*;
use group::GroupEncoding;
use rand_chacha::{
    ChaCha20Rng,
    rand_core::{RngCore, SeedableRng},
};
use sha2::{Digest, Sha256};

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    out
}

fn run<C: PastaCurve>(curve: &str, workers: usize, mode: &str, shape: &str) {
    const N: usize = 65536;
    const FREE: usize = 2_430_144;
    const HELD: usize = PROCESS_MSM_SCRATCH_BYTES - FREE;
    let setup = Instant::now();
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(workers)
        .build()
        .unwrap();
    let mut rng = ChaCha20Rng::seed_from_u64(0x0073_7472_6561_6d31);
    let mut scalars: Vec<C::ScalarExt> = (0..N)
        .map(|index| {
            if shape == "full_width" || index >= N - 5 {
                C::ScalarExt::random(&mut rng)
            } else if index % 8 == 0 {
                C::ScalarExt::from(u64::from(rng.next_u32() & 65535))
            } else {
                C::ScalarExt::ZERO
            }
        })
        .collect();
    let mut points = Vec::with_capacity(N);
    let mut point = C::identity();
    let mut expected_scalar = C::ScalarExt::ZERO;
    let mut input_hash = Sha256::new();
    for (index, scalar) in scalars.iter().enumerate() {
        point += C::generator();
        points.push(point);
        expected_scalar += *scalar * C::ScalarExt::from((index + 1) as u64);
        for limb in scalar.to_canonical_limbs() {
            input_hash.update(limb.to_le_bytes());
        }
    }
    let expected = C::generator() * expected_scalar;
    let mut bases = vec![C::AffineExt::identity(); N];
    C::batch_normalize(&points, &mut bases);
    drop(points);
    for base in &bases {
        input_hash.update(base.to_bytes().as_ref());
    }
    let input_sha256 = hex(&input_hash.finalize());
    let shared = SharedMemoryBudget::new(PROCESS_MSM_SCRATCH_BYTES);
    // A separate single-test process is mandatory. If another MSM owns scratch,
    // this refusal invalidates the attempt instead of weakening the condition.
    let held = shared
        .try_reserve(HELD)
        .expect("exclusive diagnostic process scratch");
    assert!(pippenger::plan(N, 255, workers, FREE).is_none());
    let chunk = pippenger::plan(N / 2, 255, workers, FREE).expect("a smaller chunk must fit");
    assert_eq!(shared.available_bytes(), FREE);
    let setup_ns = setup.elapsed().as_nanos();
    let mut samples = Vec::new();
    pool.install(|| {
        assert_eq!(rayon::current_num_threads(), workers);
        for _ in 0..2 {
            let start = Instant::now();
            let actual = match mode {
                "stream" => msm_secret_with_shared_budget::<C>(
                    &scalars,
                    &bases,
                    MemoryBudget::DEFAULT,
                    &shared,
                ),
                "stack" => small_msm::<C, true>(&scalars, &bases, None),
                _ => unreachable!("validated mode"),
            }
            .unwrap();
            samples.push(start.elapsed().as_nanos());
            assert_eq!(actual, expected, "independent weighted-generator relation");
            assert_eq!(shared.in_use_bytes(), HELD);
        }
    });
    if mode == "stream" {
        assert!(shared.peak_bytes() > HELD, "must exercise admitted chunks");
    } else {
        assert_eq!(shared.peak_bytes(), HELD);
    }
    assert!(shared.peak_bytes() <= PROCESS_MSM_SCRATCH_BYTES);
    drop(held);
    assert_eq!(shared.in_use_bytes(), 0);
    println!(
        "MSM_STREAM_DIAGNOSTIC curve={curve} workers={workers} mode={mode} shape={shape} n={N} secret_bits=255 held={HELD} free={FREE} setup_ns={setup_ns} samples_ns={samples:?} chunk_scratch={} reserved_peak={} input_sha256={input_sha256} result_sha256={} scope=forced_contention_only",
        chunk.bytes,
        shared.peak_bytes(),
        hex(&Sha256::digest(expected.to_affine().to_bytes().as_ref()))
    );
    scalars.iter_mut().zeroize();
}

#[test]
#[ignore = "explicit isolated fresh-process forced-contention comparison; not an M3 gate"]
fn forced_streaming_contention_diagnostic() {
    let curve = std::env::var("KAGEMUSHA_MSM_STREAM_CURVE").unwrap();
    let workers = std::env::var("KAGEMUSHA_MSM_STREAM_WORKERS")
        .unwrap()
        .parse::<usize>()
        .unwrap();
    let mode = std::env::var("KAGEMUSHA_MSM_STREAM_MODE").unwrap();
    let shape = std::env::var("KAGEMUSHA_MSM_STREAM_SHAPE").unwrap();
    assert!(matches!(workers, 1 | 4));
    assert!(matches!(mode.as_str(), "stream" | "stack"));
    assert!(matches!(shape.as_str(), "full_width" | "sparse_blinded"));
    match curve.as_str() {
        "pallas" => run::<Ep>(&curve, workers, &mode, &shape),
        "vesta" => run::<Eq>(&curve, workers, &mode, &shape),
        _ => panic!("explicit supported curve"),
    }
}
