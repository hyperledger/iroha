//! Positive, direct-witness and native-proof controls for compact ARX words.

use super::*;
use crate::ram_lfe_test_support::{NativeProof, check};
use iroha_plonk::{
    cs::Instance,
    frontend::{Circuit, SimpleFloorPlanner},
};
use std::{sync::Arc, time::Instant};

#[derive(Clone)]
struct Arithmetic<const N: usize, const ROT: u32, const FUSED: bool = false> {
    values: Arc<Zeroizing<[u64; 3]>>,
    faults: Vec<Fault>,
    forge_source: bool,
    fail_after_load: bool,
    panic_after_load: bool,
}

impl<const N: usize, const ROT: u32, const FUSED: bool> Arithmetic<N, ROT, FUSED> {
    fn new(values: [u64; 3]) -> Self {
        Self {
            values: Arc::new(Zeroizing::new(values)),
            faults: Vec::new(),
            forge_source: false,
            fail_after_load: false,
            panic_after_load: false,
        }
    }

    fn expected(&self) -> Vec<Scalar> {
        let [a, b, c] = **self.values;
        let value = if N == 8 {
            u64::from(
                ((a as u32).wrapping_add(b as u32).wrapping_add(c as u32) ^ a as u32)
                    .rotate_right(ROT),
            )
        } else {
            (a.wrapping_add(b).wrapping_add(c) ^ a).rotate_right(ROT)
        };
        (0..N)
            .map(|i| Scalar::from((value >> (4 * i)) & 15))
            .collect()
    }
}

impl<const N: usize, const ROT: u32, const FUSED: bool> Circuit<Scalar>
    for Arithmetic<N, ROT, FUSED>
{
    type Config = (WordConfig, Column<Instance>);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self::new([0; 3])
    }

    fn configure(meta: &mut ConstraintSystem<Scalar>) -> Self::Config {
        let config = WordConfig::configure(meta);
        let instance = meta.instance_column(N);
        meta.enable_equality(instance);
        (config, instance)
    }

    fn synthesize(
        &self,
        (config, instance): Self::Config,
        mut layouter: impl Layouter<Scalar>,
    ) -> Result<(), Error> {
        config.load_table(&mut layouter)?;
        let output = layouter.assign_region(
            || "fixed compact ARX control",
            |mut region| {
                let mut words = WordRegion {
                    config: &config,
                    region: &mut region,
                    offset: 0,
                    faults: &self.faults,
                };
                let mut a = words.load::<N>(self.values[0], false)?;
                let b = words.load::<N>(self.values[1], false)?;
                let c = words.load::<N>(self.values[2], false)?;
                if self.fail_after_load {
                    return Err(Error::Synthesis);
                }
                assert!(!self.panic_after_load, "test-only synthesis unwind");
                if self.forge_source {
                    *a.value ^= 1;
                }
                let sum = words.add(&a, &b, &c)?;
                let output = if FUSED {
                    words.xor_rotate_right(&sum, &a, ROT)?
                } else {
                    let xor = words.xor(&sum, &a)?;
                    words.rotate_right(&xor, ROT)?
                };
                let expected_rows = 5 * N + usize::from(!FUSED && ROT % 4 != 0) * N;
                assert_eq!(words.offset, expected_rows, "fixed layout row count");
                Ok(output)
            },
        )?;
        for (row, &cell) in output.cells.iter().enumerate() {
            layouter.constrain_instance(cell, instance, row)?;
        }
        Ok(())
    }
}

fn assert_valid<const N: usize, const ROT: u32>(values: [u64; 3]) {
    let circuit = Arithmetic::<N, ROT>::new(values);
    check(12, &circuit, vec![circuit.expected()])
        .expect("bounded layout")
        .into_result()
        .expect("all constraints hold");
}

#[test]
fn compact_words_match_native_overflow_and_all_hash_rotations() {
    for values in [
        [0; 3],
        [u64::MAX; 3],
        [1, u64::MAX, 0],
        [
            0x0123_4567_89ab_cdef,
            0xfedc_ba98_7654_3210,
            0xa5a5_5a5a_a5a5_5a5a,
        ],
    ] {
        assert_valid::<16, 0>(values);
        assert_valid::<16, 16>(values);
        assert_valid::<16, 24>(values);
        assert_valid::<16, 32>(values);
        assert_valid::<16, 63>(values);
        assert_valid::<16, 64>(values);
        let values = values.map(|value| value & u64::from(u32::MAX));
        assert_valid::<8, 7>(values);
        assert_valid::<8, 8>(values);
        assert_valid::<8, 12>(values);
        assert_valid::<8, 16>(values);
        assert_valid::<8, 32>(values);
    }
}

fn assert_fused<const N: usize, const ROT: u32>(values: [u64; 3]) {
    let circuit = Arithmetic::<N, ROT, true>::new(values);
    check(12, &circuit, vec![circuit.expected()])
        .expect("layout")
        .into_result()
        .expect("all constraints hold");
}

#[test]
fn fused_xor_rotation_matches_every_hash_rotation() {
    for values in [
        [0; 3],
        [u64::MAX; 3],
        [0x0123_4567_89ab_cdef, 42, 0xa5a5_5a5a_a5a5_5a5a],
    ] {
        assert_fused::<16, 16>(values);
        assert_fused::<16, 24>(values);
        assert_fused::<16, 32>(values);
        assert_fused::<16, 63>(values);
        let values = values.map(|value| value & u64::from(u32::MAX));
        assert_fused::<8, 7>(values);
        assert_fused::<8, 8>(values);
        assert_fused::<8, 12>(values);
        assert_fused::<8, 16>(values);
    }
    let original = Arithmetic::<16, 63, true>::new([1, 0xfedc_ba98_7654_3210, 7]);
    for (column, value) in [(0, 16), (1, 16), (2, 8), (3, 16), (4, 8), (5, 2)] {
        let mut circuit = original.clone();
        circuit.faults = vec![Fault {
            row: 64,
            column,
            value: Scalar::from(value),
        }];
        assert!(
            check(12, &circuit, vec![original.expected()])
                .expect("layout")
                .into_result()
                .is_err()
        );
    }
}

#[test]
fn compact_words_reject_direct_assignment_mutations() {
    let original = Arithmetic::<16, 63>::new([
        0x0123_4567_89ab_cdef,
        0xfedc_ba98_7654_3210,
        0xa5a5_5a5a_a5a5_5a5a,
    ]);
    // The exact layout is 48 input rows, 16 addition rows, 16 XOR rows,
    // and 16 rotation rows. These mutations bypass every native validator.
    for (label, row, column, value) in [
        ("noncanonical input nibble", 0, 0, 16),
        ("nonzero initial carry", 48, 4, 1),
        ("noncanonical carry", 49, 4, 3),
        ("wrong addition result", 48, 3, 0),
        ("wrong terminal overflow", 63, 5, 2),
        ("wrong XOR output", 64, 3, 0),
        ("out-of-range XOR input", 64, 0, 16),
        ("oversized rotation low part", 80, 2, 8),
        ("oversized rotation high part", 80, 5, 2),
        ("wrong rotated output", 80, 3, 0),
        ("unbound wraparound low part", 95, 4, 0),
    ] {
        let mut circuit = original.clone();
        circuit.faults = vec![Fault {
            row,
            column,
            value: Scalar::from(value),
        }];
        let prover = check(12, &circuit, vec![original.expected()]).expect("layout");
        assert!(prover.into_result().is_err(), "mutation survived: {label}");
    }
    let mut circuit = original.clone();
    circuit.forge_source = true;
    assert!(
        check(12, &circuit, vec![original.expected()])
            .expect("layout")
            .into_result()
            .is_err()
    );
    let mut wrong_public = original.expected();
    wrong_public[0] += Scalar::ONE;
    assert!(
        check(12, &original, vec![wrong_public])
            .expect("layout")
            .into_result()
            .is_err()
    );
}

#[test]
fn compact_words_reject_32_bit_input_overflow_before_assignment() {
    let circuit = Arithmetic::<8, 7>::new([u64::from(u32::MAX) + 1, 0, 0]);
    assert!(check(12, &circuit, vec![vec![Scalar::ZERO; 8]]).is_err());
}

#[derive(Clone)]
struct RotationOnly {
    faults: Vec<Fault>,
    constant: bool,
}

impl Circuit<Scalar> for RotationOnly {
    type Config = WordConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self {
            faults: Vec::new(),
            constant: self.constant,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Scalar>) -> Self::Config {
        WordConfig::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Scalar>,
    ) -> Result<(), Error> {
        config.load_table(&mut layouter)?;
        layouter.assign_region(
            || "rotation without downstream range or public output",
            |mut region| {
                let mut words = WordRegion {
                    config: &config,
                    region: &mut region,
                    offset: 0,
                    faults: &self.faults,
                };
                let word = words.load::<16>(1, self.constant)?;
                let _unexposed = words.rotate_right(&word, 1)?;
                Ok(())
            },
        )
    }
}

#[test]
fn compact_rotation_rejects_fractional_split_without_downstream_checks() {
    let valid = RotationOnly {
        faults: Vec::new(),
        constant: false,
    };
    check(12, &valid, vec![])
        .expect("layout")
        .into_result()
        .expect("all constraints hold");
    let half = Scalar::from(2).invert().expect("nonzero field denominator");
    // Scaled-only bounds admit input=1, lo=0, hi=1/2, output=1/2.
    // Coordinate the wraparound next-low and terminal output as well, so all
    // copy constraints hold. Only the integer tuple lookup rejects this.
    assert_eq!(half * Scalar::from(2), Scalar::ONE);
    let circuit = RotationOnly {
        faults: vec![
            Fault {
                row: 16,
                column: 2,
                value: Scalar::ZERO,
            },
            Fault {
                row: 16,
                column: 5,
                value: half,
            },
            Fault {
                row: 16,
                column: 3,
                value: half,
            },
            Fault {
                row: 31,
                column: 3,
                value: Scalar::ZERO,
            },
            Fault {
                row: 31,
                column: 4,
                value: Scalar::ZERO,
            },
        ],
        constant: false,
    };
    let failures = check(12, &circuit, vec![])
        .expect("layout")
        .into_result()
        .expect_err("fractional split cannot become a word token");
    assert!(failures.iter().all(|failure| matches!(
        failure,
        iroha_plonk::check::CheckFailure::LookupInputMissing { .. }
    )));
}

#[test]
fn compact_constant_words_are_bound_to_their_cells() {
    let circuit = RotationOnly {
        faults: Vec::new(),
        constant: true,
    };
    check(12, &circuit, vec![])
        .expect("layout")
        .into_result()
        .expect("all constraints hold");
    let circuit = RotationOnly {
        faults: vec![Fault {
            row: 0,
            column: 0,
            value: Scalar::from(2),
        }],
        constant: true,
    };
    assert!(
        check(12, &circuit, vec![])
            .expect("layout")
            .into_result()
            .is_err()
    );
}

#[test]
fn compact_owned_words_clear_on_success_error_and_unwind() {
    for (fail, panic) in [(false, false), (true, false), (false, true)] {
        let before = CLEARED_WORDS.with(std::cell::Cell::get);
        let mut circuit = Arithmetic::<16, 63>::new([u64::MAX; 3]);
        circuit.fail_after_load = fail;
        circuit.panic_after_load = panic;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            check(12, &circuit, vec![circuit.expected()])
        }));
        if panic {
            assert!(result.is_err());
        } else if fail {
            assert!(result.expect("no unwind").is_err());
        } else {
            result
                .expect("no unwind")
                .expect("layout")
                .into_result()
                .expect("all constraints hold");
        }
        assert!(CLEARED_WORDS.with(std::cell::Cell::get) >= before + 3);
    }
}

#[test]
fn compact_word_geometry_pins_capacity_inputs() {
    let mut meta = ConstraintSystem::default();
    let _ = Compression::configure(&mut meta);
    assert_eq!(meta.degree(), 5);
    assert_eq!(meta.num_advice_columns(), 6);
    assert_eq!(meta.advice_queries().len(), 6);
    assert!(
        meta.advice_queries()
            .iter()
            .all(|(_, rotation)| *rotation == Rotation::cur())
    );
    assert_eq!(meta.lookups().len(), 1);
    assert_eq!(meta.permutation().columns().len(), 8);
    assert_eq!(meta.blinding_factors(), 5);
    assert_eq!(meta.minimum_rows(), 8);
    println!(
        "RAM_LFE_GEOMETRY_METRICS degree={} advice_columns={} advice_queries={} fixed_columns_before_selector_compression={} fixed_queries_before_selector_compression={} lookup_arguments={} permutation_columns={} permutation_chunk_columns={} blinding_factors={} minimum_rows={}",
        meta.degree(),
        meta.num_advice_columns(),
        meta.advice_queries().len(),
        meta.num_fixed_columns(),
        meta.fixed_queries().len(),
        meta.lookups().len(),
        meta.permutation().columns().len(),
        meta.degree() - 2,
        meta.blinding_factors(),
        meta.minimum_rows(),
    );
}

#[test]
fn compact_word_native_ipa_proof_metrics_and_rejection_controls() {
    let circuit = Arithmetic::<16, 63, true>::new([u64::MAX, 0x1234_5678_9abc_def0, 42]);
    let params_started = Instant::now();
    let setup = NativeProof::new(12, &circuit);
    let vk_bytes = setup.key_bytes();
    let keygen_ms = params_started.elapsed().as_secs_f64() * 1000.0;
    let public = circuit.expected();
    let prove_started = Instant::now();
    let proof = setup.prove(circuit, &public);
    let prove_ms = prove_started.elapsed().as_secs_f64() * 1000.0;
    let verify_started = Instant::now();
    setup.verify(&public, &proof).expect("word verification");
    let verify_ms = verify_started.elapsed().as_secs_f64() * 1000.0;
    assert!(proof.len() < 192 * 1024);
    println!(
        "RAM_LFE_WORD_METRICS k=12 advice_columns=6 table_rows=3905 operation_rows=80 proof_bytes={} vk_bytes={vk_bytes} keygen_ms={keygen_ms:.3} prove_ms={prove_ms:.3} verify_ms={verify_ms:.3}",
        proof.len(),
    );
    let mut wrong_public = public.clone();
    wrong_public[0] += Scalar::ONE;
    assert!(setup.verify(&wrong_public, &proof).is_err());
    let mut suffixed = proof.clone();
    suffixed.push(0);
    assert!(setup.verify(&public, &suffixed).is_err());
    let mut changed = proof;
    changed[0] ^= 1;
    assert!(setup.verify(&public, &changed).is_err());
}

// First64 output bytes from the official BLAKE3 1.8.5 test vectors at
// https://github.com/BLAKE3-team/BLAKE3/blob/1.8.5/test_vectors/test_vectors.json.
// Input byte i equals i modulo251. These three inputs fit one root block.
const COMPRESSION_KATS: [(usize, [u32; 16]); 3] = [
    (
        0,
        [
            0xb94913af, 0xa6a1f9f5, 0xea4d40a0, 0x49c9dc36, 0xc925cb9b, 0xb712c1ad, 0xca939acc,
            0x62321fe4, 0xe7030fe0, 0x6bf29ab6, 0x9ff0aa7f, 0x503033cd, 0xe0df8d33, 0x86ccb885,
            0x208ba99c, 0x3a24086c,
        ],
    ),
    (
        3,
        [
            0x7a4dbee1, 0x0a56b58a, 0xea9e19a4, 0xba499833, 0x553d298e, 0x00810aca, 0x84d12667,
            0x7f649e51, 0x2fb8495b, 0x8c535a80, 0x1a5c9168, 0x905c03e8, 0xb1d4d10f, 0x0f920239,
            0x50145ed0, 0xde362f82,
        ],
    ),
    (
        64,
        [
            0x4171ed4e, 0xd45c4aea, 0x6b6088b7, 0xe2463fd2, 0xac9caf12, 0x7ddcaceb, 0xc76d4c1f,
            0x981b51f2, 0x6cc59cfc, 0xe3ff31b8, 0xe1e7a83e, 0xb209dfd1, 0x6727fd6e, 0xaa660067,
            0xb123d082, 0x1babe8df,
        ],
    ),
];

#[derive(Clone)]
struct Compression {
    inputs: Arc<Zeroizing<[u64; 28]>>,
    faults: Vec<Fault>,
}

impl Compression {
    fn vector(length: usize) -> Self {
        let mut inputs = Zeroizing::new([0; 28]);
        inputs[..8].copy_from_slice(&[
            0x6a09_e667,
            0xbb67_ae85,
            0x3c6e_f372,
            0xa54f_f53a,
            0x510e_527f,
            0x9b05_688c,
            0x1f83_d9ab,
            0x5be0_cd19,
        ]);
        for i in 0..length {
            inputs[8 + i / 4] |= (i as u64) << (8 * (i % 4));
        }
        inputs[26] = length as u64;
        inputs[27] = 1 | 2 | 8; // CHUNK_START | CHUNK_END | ROOT
        Self {
            inputs: Arc::new(inputs),
            faults: Vec::new(),
        }
    }

    fn public(expected: &[u32; 16]) -> Vec<Scalar> {
        expected
            .iter()
            .flat_map(|&word| (0..8).map(move |i| Scalar::from(u64::from((word >> (4 * i)) & 15))))
            .collect()
    }
}

impl Circuit<Scalar> for Compression {
    type Config = (WordConfig, Column<Instance>);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self {
            inputs: Arc::new(Zeroizing::new([0; 28])),
            faults: Vec::new(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<Scalar>) -> Self::Config {
        let config = WordConfig::configure(meta);
        let instance = meta.instance_column(128);
        meta.enable_equality(instance);
        (config, instance)
    }

    fn synthesize(
        &self,
        (config, instance): Self::Config,
        mut layouter: impl Layouter<Scalar>,
    ) -> Result<(), Error> {
        config.load_table(&mut layouter)?;
        let output = layouter.assign_region(
            || "exact BLAKE3 compression",
            |mut region| {
                let mut words = WordRegion {
                    config: &config,
                    region: &mut region,
                    offset: 0,
                    faults: &self.faults,
                };
                let mut inputs = self
                    .inputs
                    .iter()
                    .map(|&value| words.load::<8>(value, false))
                    .collect::<Result<Vec<_>, _>>()?
                    .into_iter();
                let chaining =
                    std::array::from_fn(|_| inputs.next().expect("eight chaining words"));
                let message =
                    std::array::from_fn(|_| inputs.next().expect("sixteen message words"));
                let counter = std::array::from_fn(|_| inputs.next().expect("two counter words"));
                let length = inputs.next().expect("length word");
                let flags = inputs.next().expect("flags word");
                let output =
                    words.blake3_compress(&chaining, &message, &counter, &length, &flags)?;
                assert_eq!(words.offset, 3976, "public compression layout");
                Ok(output)
            },
        )?;
        for (i, word) in output.iter().enumerate() {
            for (nibble, &cell) in word.cells.iter().enumerate() {
                layouter.constrain_instance(cell, instance, 8 * i + nibble)?;
            }
        }
        Ok(())
    }
}

#[test]
fn blake3_compression_matches_official_single_block_vectors() {
    for (length, expected) in COMPRESSION_KATS {
        let circuit = Compression::vector(length);
        check(12, &circuit, vec![Compression::public(&expected)])
            .expect("compression layout")
            .into_result()
            .expect("all constraints hold");
    }
}

#[test]
fn blake3_compression_rejects_changed_inputs_and_internal_field_assignments() {
    let public = Compression::public(&COMPRESSION_KATS[0].1);
    let original = Compression::vector(0);
    for index in [0, 7, 8, 23, 24, 25, 26, 27] {
        let mut inputs = Zeroizing::new(**original.inputs);
        inputs[index] ^= 1;
        let circuit = Compression {
            inputs: Arc::new(inputs),
            faults: Vec::new(),
        };
        assert!(
            check(12, &circuit, vec![public.clone()])
                .expect("layout")
                .into_result()
                .is_err(),
            "unbound input word {index}"
        );
    }
    let half = Scalar::from(2).invert().expect("nonzero denominator");
    for (label, row, column, value) in [
        ("first round sum", 264, 3, Scalar::ONE),
        ("first round carry", 264, 5, Scalar::from(2)),
        ("fractional internal result", 264, 3, half),
        ("message schedule copy", 264, 2, Scalar::ONE),
        ("last compression output", 3975, 3, half),
    ] {
        let mut circuit = original.clone();
        circuit.faults = vec![Fault { row, column, value }];
        assert!(
            check(12, &circuit, vec![public.clone()])
                .expect("layout")
                .into_result()
                .is_err(),
            "mutation survived: {label}"
        );
    }
}

#[test]
fn blake3_compression_native_ipa_proof_and_metrics() {
    let circuit = Compression::vector(3);
    let params_started = Instant::now();
    let setup = NativeProof::new(12, &circuit);
    let vk_bytes = setup.key_bytes();
    let keygen_ms = params_started.elapsed().as_secs_f64() * 1000.0;
    let public = Compression::public(&COMPRESSION_KATS[1].1);
    let prove_started = Instant::now();
    let proof = setup.prove(circuit, &public);
    let prove_ms = prove_started.elapsed().as_secs_f64() * 1000.0;
    let verify_started = Instant::now();
    setup
        .verify(&public, &proof)
        .expect("compression verification");
    let verify_ms = verify_started.elapsed().as_secs_f64() * 1000.0;
    assert!(proof.len() < 192 * 1024);
    println!(
        "RAM_LFE_BLAKE3_METRICS k=12 advice_columns=6 table_rows=3905 operation_rows=3976 proof_bytes={} vk_bytes={vk_bytes} keygen_ms={keygen_ms:.3} prove_ms={prove_ms:.3} verify_ms={verify_ms:.3}",
        proof.len()
    );
    let mut wrong_public = public.clone();
    wrong_public[0] += Scalar::ONE;
    assert!(setup.verify(&wrong_public, &proof).is_err());
    let mut changed = proof.clone();
    changed[0] ^= 1;
    assert!(setup.verify(&public, &changed).is_err());
    changed = proof;
    changed.push(0);
    assert!(setup.verify(&public, &changed).is_err());
}
