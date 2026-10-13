//! Raw randomized timing screen of the actual serial T256 secret MSM owner.
//!
//! This produces public diagnostic samples, not a constant-time certificate.
//! Run on a quiet host and retain the executable, source and hardware identity.
//! The public variable-time MSM is an intentional positive leakage control.

use std::{
    hint::black_box,
    io::{self, Write},
    time::Instant,
};

use super::{VegaT256PointV1 as Point, VegaT256ScalarV1 as Scalar, derive_t256_generators_v1};
use crate::generalized_bulletproof::{
    ProofGenerators, ProofSuite, SecretMultiexpBuilder, multiexp,
};

/// Match the private T256 suite's arithmetic types and serial workspace policy.
/// Generator derivation is explicit and outside every measured operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TimingSuite;

impl ProofSuite for TimingSuite {
    type Scalar = Scalar;
    type Point = Point;
    const ALLOW_PARALLEL_PROVER_WORKSPACE_V1: bool = false;
    fn generators() -> &'static ProofGenerators<Self> {
        panic!("secret MSM must use the caller's explicit public bases")
    }
}

/// Deterministic public fixture/order generator. Never used for real secrets.
struct PublicFixture(u64);
impl PublicFixture {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn scalar(&mut self) -> Scalar {
        let mut bytes = [0_u8; 64];
        for chunk in bytes.chunks_exact_mut(8) {
            chunk.copy_from_slice(&self.next().to_le_bytes());
        }
        let value = Scalar::from_uniform_le_bytes_ref(&bytes);
        bytes.fill(0);
        value
    }
}

/// Keep fixture owners symmetric across classes, even though values are public.
struct Fixture(Vec<Scalar>);
impl Drop for Fixture {
    fn drop(&mut self) {
        for value in &mut self.0 {
            value.clear_secret();
        }
    }
}

fn secret_msm(values: &[Scalar], points: &[Point]) {
    let mut terms = SecretMultiexpBuilder::<TimingSuite>::new(values.len()).unwrap();
    for (value, point) in values.iter().zip(points) {
        terms.push(black_box(value), black_box(point)).unwrap();
    }
    let point = terms.evaluate().unwrap();
    black_box(point.expose_ref());
    drop(point);
}

fn public_msm(values: &[Scalar], points: &[Point]) {
    let terms: Vec<_> = values.iter().copied().zip(points.iter().copied()).collect();
    black_box(multiexp::<TimingSuite>(black_box(&terms)));
}

fn fixtures(terms: usize, sparse: bool, rng: &mut PublicFixture) -> [Fixture; 2] {
    let mut low = vec![Scalar::zero(); terms];
    let mut dense: Vec<_> = (0..terms).map(|_| rng.scalar()).collect();
    if sparse {
        for value in &mut low[..terms - 1] {
            let bit = rng.next() as usize % 255;
            let mut bytes = [0_u8; 32];
            bytes[bit / 8] = 1 << (bit % 8);
            *value = Scalar::from_le_bytes_exact(bytes).unwrap();
            bytes.fill(0);
        }
    }
    // Both classes share a nonzero blinding; the zero-prefix result is nonzero.
    let blinding = rng.scalar();
    let blinding = if blinding == Scalar::zero() {
        Scalar::one()
    } else {
        blinding
    };
    low[terms - 1] = blinding;
    dense[terms - 1] = blinding;
    [Fixture(low), Fixture(dense)]
}

fn check_arithmetic(values: &[Scalar], points: &[Point]) {
    let mut terms = SecretMultiexpBuilder::<TimingSuite>::new(values.len()).unwrap();
    let mut expected = points[0].mul_scalar(Scalar::zero());
    for (value, point) in values.iter().zip(points) {
        terms.push(value, point).unwrap();
        expected += point.mul_scalar(*value);
    }
    assert!(terms.evaluate().unwrap().equals(&expected));
    // Check the intentional variable-time control against the same direct
    // multiplication oracle before measuring either implementation.
    let public_terms: Vec<_> = values.iter().copied().zip(points.iter().copied()).collect();
    assert_eq!(multiexp::<TimingSuite>(&public_terms), expected);
}

/// Run the explicitly enabled diagnostic using the actual private T256 adapter.
///
/// Writes every raw randomized pair to stdout. This finite timing screen does
/// not establish constant-time execution; retain the binary and host conditions.
///
/// # Panics
///
/// Panics for malformed diagnostic arguments, failed arithmetic controls, or
/// allocation/output failures. No production credentials are accepted.
#[doc(hidden)]
pub fn run_vega_secret_msm_timing_screen() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    assert!(
        args.len() <= 1,
        "usage: vega_secret_msm_timing [pairs_per_case]"
    );
    let pairs = args
        .first()
        .map_or(4096, |value| value.parse::<usize>().expect("integer pairs"));
    assert!(
        (128..=65_536).contains(&pairs),
        "pairs must lie in 128..=65536"
    );
    let mut fixture_rng = PublicFixture(0x5e7a_1c03_d9f2_8b61);
    let mut order_rng = PublicFixture(0x8ac7_4193_0def_652b);
    let points =
        derive_t256_generators_v1(b"vega-secret-msm-timing-public-fixture-v1", 257).unwrap();
    let mut samples = Vec::with_capacity(pairs.checked_mul(16).unwrap());
    // Two terms covers a populated value and blinding. 257 crosses the shared
    // owner's 256-term chunk boundary. Both class labels have identical sizes.
    for terms in [2, 17, 257] {
        for sparse in [false, true] {
            let values = fixtures(terms, sparse, &mut fixture_rng);
            for fixture in &values {
                check_arithmetic(&fixture.0, &points[..terms]);
            }
            for _ in 0..32 {
                for fixture in &values {
                    secret_msm(&fixture.0, &points[..terms]);
                }
            }
            for pair in 0..pairs {
                let values = fixtures(terms, sparse, &mut fixture_rng);
                let first = (order_rng.next() & 1) as usize;
                for position in 0..2 {
                    let class = first ^ position;
                    let started = Instant::now();
                    secret_msm(black_box(&values[class].0), black_box(&points[..terms]));
                    let elapsed = started.elapsed().as_nanos();
                    samples.push(("secret", terms, sparse, pair, position, class, elapsed));
                }
            }
        }
    }
    // This public API deliberately branches on scalar windows. If this control
    // shows no detectable difference, a clean secret result is inconclusive.
    for terms in [17, 257] {
        let warmup = fixtures(terms, false, &mut fixture_rng);
        for fixture in &warmup {
            check_arithmetic(&fixture.0, &points[..terms]);
        }
        for _ in 0..32 {
            for fixture in &warmup {
                public_msm(&fixture.0, &points[..terms]);
            }
        }
        for pair in 0..pairs {
            let values = fixtures(terms, false, &mut fixture_rng);
            let first = (order_rng.next() & 1) as usize;
            for position in 0..2 {
                let class = first ^ position;
                let started = Instant::now();
                public_msm(black_box(&values[class].0), black_box(&points[..terms]));
                samples.push((
                    "public_control",
                    terms,
                    false,
                    pair,
                    position,
                    class,
                    started.elapsed().as_nanos(),
                ));
            }
        }
    }
    // No formatted output or disk I/O occurs within any measurement case.
    let mut out = io::BufWriter::new(io::stdout().lock());
    writeln!(out, "path,terms,sparse,pair,position,class,nanoseconds").unwrap();
    for (path, terms, sparse, pair, position, class, nanos) in samples {
        writeln!(
            out,
            "{path},{terms},{sparse},{pair},{position},{class},{nanos}"
        )
        .unwrap();
    }
}
