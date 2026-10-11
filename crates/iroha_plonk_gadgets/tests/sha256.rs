//! The SHA-256 chip (M3 gadget `sha256`): the FIPS 180 vectors, the gate
//! degree, SHA-256 of a Poseidon digest against native references, the
//! G3.3 measurement at the Q-leaf shape, and real Pallas proofs.

use std::{convert::Infallible, time::Instant};

use ff::{Field as _, PrimeField as _};
use iroha_pasta::{Ep, Fp, Fq, PastaField, msm::MemoryBudget, poseidon::hash_with_domain};
use iroha_plonk::{
    Expression, ProverConfig, ProverRandomness,
    check::{CheckMode, check_circuit},
    cs::{Advice, Column, ConstraintSystem, Instance, InstanceModeV1, ProofSuffixV1, TranscriptV1},
    frontend::{Circuit, Error, Layouter, SimpleFloorPlanner, Value, configure, synthesize},
    keys::{KeygenConfig, keygen_pk},
    pcs::ipa::PinnedParams,
    prove_circuit, verify_full,
};
use iroha_plonk_gadgets::{
    GlueChip, GlueConfig, MAX_GATE_DEGREE,
    q_leaf::Q_LEAF_ADVICE_COLUMNS,
    sha256::{
        DIGEST_CODEC_ROWS, HASH_DIGEST_ROWS, SHA256_ADVICE_COLUMNS, Sha256Chip, Sha256Config,
        Sha256State, Sha256Word, TABLE_ROWS,
        native::{digest_message, pad, sha256},
    },
};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use sha2::{Digest as _, Sha256};

/// The Q-leaf advice width (`specs/kagemusha_lambda_omega_v1.md` section 2;
/// the leaf layout of `iroha_plonk_gadgets::q_leaf`).
const Q_ADVICE_COLUMNS: usize = Q_LEAF_ADVICE_COLUMNS;

/// The G3.3 thresholds per block.
const G3_3_MAX_ROWS: usize = 2_800;
const G3_3_MAX_CELLS: usize = 50_000;

/// What the circuit hashes.
#[derive(Clone, Debug)]
enum Mode<F> {
    /// The padded `message`, its words witnessed.
    Message(Vec<u8>),
    /// The 32-byte canonical encoding of `digest`, a value of `Fp` (when
    /// `fp`) or `Fq` held as the integer in a cell of `F`.
    Digest { digest: F, fp: bool },
}

/// The circuit shape: the chip, a glue chip and spare advice columns up to
/// `width`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Shape {
    width: usize,
}

impl Default for Shape {
    fn default() -> Self {
        Self {
            width: SHA256_ADVICE_COLUMNS + 4,
        }
    }
}

#[derive(Clone, Debug)]
struct ShaCircuit<F> {
    mode: Mode<F>,
    shape: Shape,
    known: bool,
}

impl<F> ShaCircuit<F> {
    fn new(mode: Mode<F>) -> Self {
        Self {
            mode,
            shape: Shape::default(),
            known: true,
        }
    }

    fn q_shaped(mut self) -> Self {
        self.shape.width = Q_ADVICE_COLUMNS;
        self
    }
}

#[derive(Clone, Debug)]
struct ShaConfig {
    sha: Sha256Config,
    glue: GlueConfig,
    instance: Column<Instance>,
}

impl<F: PastaField> Circuit<F> for ShaCircuit<F> {
    type Config = ShaConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = Shape;

    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }

    fn params(&self) -> Shape {
        self.shape
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        Self::configure_with_params(meta, Shape::default())
    }

    fn configure_with_params(meta: &mut ConstraintSystem<F>, shape: Shape) -> Self::Config {
        let advice: [Column<Advice>; SHA256_ADVICE_COLUMNS] =
            core::array::from_fn(|_| meta.advice_column());
        let constants = meta.fixed_column();
        let sha = Sha256Config::configure(meta, advice, constants);
        let glue_advice = core::array::from_fn(|_| meta.advice_column());
        let glue = GlueConfig::configure(meta, glue_advice, constants);
        for _ in SHA256_ADVICE_COLUMNS + 4..shape.width {
            meta.advice_column();
        }
        let instance = meta.instance_column(8);
        meta.enable_equality(instance);
        ShaConfig {
            sha,
            glue,
            instance,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let mut chip = Sha256Chip::new(&config.sha);
        let mut glue = GlueChip::new(config.glue);
        chip.load_table(&mut layouter)?;
        let known = self.known;
        let digest = layouter.assign_region(
            || "sha256",
            |mut region| match &self.mode {
                Mode::Message(message) => {
                    let mut state = Sha256State::iv();
                    let mut out = None;
                    for block in pad(message).ok_or(Error::Synthesis)? {
                        let mut words = Vec::with_capacity(16);
                        for word in block {
                            let value = if known {
                                Value::known(word)
                            } else {
                                Value::unknown()
                            };
                            words.push(Sha256Word::Assigned(chip.assign_u32(&mut region, value)?));
                        }
                        let words: [Sha256Word<F>; 16] =
                            words.try_into().map_err(|_| Error::Synthesis)?;
                        let digest = chip.compress(&mut region, &state, &words)?;
                        state = digest.state();
                        out = Some(digest);
                    }
                    out.ok_or(Error::Synthesis)
                }
                Mode::Digest { digest, fp } => {
                    let value = if known {
                        Value::known(*digest)
                    } else {
                        Value::unknown()
                    };
                    let word = glue.witness(&mut region, value)?;
                    if *fp {
                        chip.hash_digest::<Fp>(&mut region, &word)
                    } else {
                        chip.hash_digest::<Fq>(&mut region, &word)
                    }
                }
            },
        )?;
        for (row, word) in digest.words().iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.instance, row)?;
        }
        Ok(())
    }
}

/// The digest bytes as the eight public words.
fn public<F: PastaField>(digest: &[u8; 32]) -> Vec<F> {
    digest
        .chunks_exact(4)
        .map(|word| {
            F::from(u64::from(u32::from_be_bytes([
                word[0], word[1], word[2], word[3],
            ])))
        })
        .collect()
}

/// Whether the strict checker accepts `circuit` with `digest` public.
fn accepts<F: PastaField>(circuit: &ShaCircuit<F>, k: u32, digest: &[u8; 32]) -> bool {
    check_circuit(circuit, k, &[public::<F>(digest)], CheckMode::Strict)
        .is_ok_and(|report| report.is_satisfied())
}

/// The checker report as text.
fn report<F: PastaField>(circuit: &ShaCircuit<F>, k: u32, digest: &[u8; 32]) -> String {
    check_circuit(circuit, k, &[public::<F>(digest)], CheckMode::Strict).map_or_else(
        |error| format!("synthesis error: {error}"),
        |report| report.to_string(),
    )
}

/// `digest` with one bit of word `word` flipped.
fn flipped(digest: &[u8; 32], word: usize) -> [u8; 32] {
    let mut out = *digest;
    out[4 * word + 3] ^= 1;
    out
}

/// FIPS 180-2 appendix B.1 (`"abc"`) and B.2 (the 448-bit message), and the
/// SHA-256 of the empty message.
fn fips_vectors() -> [(&'static [u8], [u8; 32]); 3] {
    [
        (
            b"abc",
            hex32("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        ),
        (
            b"",
            hex32("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        ),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            hex32("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
        ),
    ]
}

fn hex32(text: &str) -> [u8; 32] {
    let mut out = [0_u8; 32];
    for (byte, pair) in out.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        let digit = |c: u8| match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("hex digit"),
        };
        *byte = digit(pair[0]) * 16 + digit(pair[1]);
    }
    out
}

#[test]
fn sha256_one_block_fips180_vectors() {
    for (message, expected) in fips_vectors().into_iter().take(2) {
        assert_eq!(pad(message).map(|blocks| blocks.len()), Some(1));
        let oracle: [u8; 32] = Sha256::digest(message).into();
        assert_eq!(oracle, expected);
        assert_eq!(sha256(message), Some(expected));
        let fq = ShaCircuit::<Fq>::new(Mode::Message(message.to_vec()));
        assert!(
            accepts(&fq, 12, &expected),
            "{}",
            report(&fq, 12, &expected)
        );
        let fp = ShaCircuit::<Fp>::new(Mode::Message(message.to_vec()));
        assert!(
            accepts(&fp, 12, &expected),
            "{}",
            report(&fp, 12, &expected)
        );
        for word in [0, 7] {
            assert!(!accepts(&fq, 12, &flipped(&expected, word)));
        }
    }
}

#[test]
fn sha256_two_block_fips180_vector_chains_the_state() {
    let (message, expected) = fips_vectors()[2];
    assert_eq!(pad(message).map(|blocks| blocks.len()), Some(2));
    let circuit = ShaCircuit::<Fq>::new(Mode::Message(message.to_vec()));
    assert!(
        accepts(&circuit, 13, &expected),
        "{}",
        report(&circuit, 13, &expected)
    );
    assert!(!accepts(&circuit, 13, &flipped(&expected, 3)));
}

#[test]
fn sha256_gate_degree_at_most_six() {
    let circuit = ShaCircuit::<Fq>::new(Mode::Digest {
        digest: Fq::from(7_u64),
        fp: true,
    });
    let (cs, _) = configure(&circuit).expect("configured");
    assert_eq!(cs.degree(), 5, "the lookup sets the degree");
    assert!(cs.degree() <= MAX_GATE_DEGREE);
    let mut gate_max = 0;
    for gate in cs.gates() {
        for poly in gate.polynomials() {
            gate_max = gate_max.max(poly.degree());
        }
    }
    assert_eq!(
        gate_max, 5,
        "the carry range x (x-1) (x-2) (x-3) is the highest gate"
    );
    assert_eq!(cs.lookups().len(), 1);
    assert_eq!(cs.lookups()[0].required_degree(), 5);
    // Every query is at rotation 0 or 1.
    for (_, rotation) in cs.advice_queries() {
        assert!((0..=1).contains(&rotation.0));
    }
    for (_, rotation) in cs.fixed_queries() {
        assert_eq!(rotation.0, 0);
    }
    // After selector compression (the key's descriptor) the degree is still
    // at most six.
    let params = PinnedParams::<Ep>::derive(12).expect("params");
    let pk = keygen_pk(
        &params,
        &circuit.without_witnesses(),
        &KeygenConfig::new(TranscriptV1::Blake2bChallenge255),
    )
    .expect("proving key");
    let descriptor = pk.binding().descriptor();
    assert!(usize::from(descriptor.degree) <= MAX_GATE_DEGREE);
    assert_eq!(descriptor.degree, 5);
    println!(
        "SHA256_DESCRIPTOR degree={} advice={} fixed_after_selector_compression={} \
         equality={} lookups={} advice_queries={} fixed_queries={}",
        descriptor.degree,
        descriptor.num_advice_columns,
        descriptor.num_fixed_columns,
        descriptor.permutation.len(),
        descriptor.lookups.len(),
        descriptor.advice_queries.len(),
        descriptor.fixed_queries.len(),
    );
}

/// `m` as the integer in a cell of `F`.
fn as_field<F: PastaField>(m: &Fp) -> F {
    F::from_repr(m.to_repr())
        .into_option()
        .expect("|Fp| <= |F|")
}

#[test]
fn sha256_of_poseidon_digest_matches_native() {
    let domain = u64::from_le_bytes(*b"kgwsign1");
    let digests = [
        hash_with_domain::<Fp>(domain, &[Fp::from(1_u64), Fp::from(2_u64), Fp::from(3_u64)]),
        hash_with_domain::<Fp>(domain, &[-Fp::ONE]),
        -Fp::ONE,
        Fp::ZERO,
    ];
    for m in digests {
        // Native references: the wire encoding is the canonical
        // little-endian 32 bytes; `sha2` hashes them.
        let message = digest_message(&m);
        assert_eq!(message, m.to_repr());
        let expected: [u8; 32] = Sha256::digest(message).into();
        // The Q-leaf placement: an Fp digest in an Fq circuit.
        let fq = ShaCircuit::<Fq>::new(Mode::Digest {
            digest: as_field(&m),
            fp: true,
        });
        assert!(
            accepts(&fq, 12, &expected),
            "{}",
            report(&fq, 12, &expected)
        );
        assert!(!accepts(&fq, 12, &flipped(&expected, 5)));
        // The native-field placement.
        let fp = ShaCircuit::<Fp>::new(Mode::Digest {
            digest: m,
            fp: true,
        });
        assert!(
            accepts(&fp, 12, &expected),
            "{}",
            report(&fp, 12, &expected)
        );
    }
    // An Fq digest in its own field.
    let m = hash_with_domain::<Fq>(domain, &[Fq::from(9_u64)]);
    let expected: [u8; 32] = Sha256::digest(m.to_repr()).into();
    let fq = ShaCircuit::<Fq>::new(Mode::Digest {
        digest: m,
        fp: false,
    });
    assert!(
        accepts(&fq, 12, &expected),
        "{}",
        report(&fq, 12, &expected)
    );
    // A cell of Fq at or above |Fp| is not an Fp digest.
    let above = Fq::from_repr((-Fp::ONE).to_repr())
        .into_option()
        .expect("p < q")
        + Fq::ONE;
    let bad = ShaCircuit::<Fq>::new(Mode::Digest {
        digest: above,
        fp: true,
    });
    let honest_bytes_hash: [u8; 32] = Sha256::digest(above.to_repr()).into();
    assert!(!accepts(&bad, 12, &honest_bytes_hash));
}

/// Rows and cells of the SHA-256 columns.
struct Inventory {
    rows: usize,
    cells: usize,
    columns: usize,
}

fn inventory<F: PastaField>(circuit: &ShaCircuit<F>, k: u32, digest: &[u8; 32]) -> Inventory {
    let synthesized = synthesize(circuit, k, Some(&[public::<F>(digest)][..])).expect("synthesis");
    let assigned = synthesized.tables.advice_assigned();
    let sha_columns = &assigned[..SHA256_ADVICE_COLUMNS];
    let rows = sha_columns
        .iter()
        .filter_map(|column| column.iter().rposition(|flag| *flag))
        .max()
        .map_or(0, |row| row + 1);
    let cells = sha_columns
        .iter()
        .map(|column| column.iter().filter(|flag| **flag).count())
        .sum();
    Inventory {
        rows,
        cells,
        columns: assigned.len(),
    }
}

#[test]
fn sha256_gate_g3_3_measurement() {
    let m = hash_with_domain::<Fp>(u64::from_le_bytes(*b"kgwsign1"), &[Fp::from(42_u64)]);
    let expected: [u8; 32] = Sha256::digest(m.to_repr()).into();
    // The Q-leaf width: 17 advice columns at k = 16.
    let digest = ShaCircuit::<Fq>::new(Mode::Digest {
        digest: as_field(&m),
        fp: true,
    })
    .q_shaped();
    let started = Instant::now();
    assert!(
        accepts(&digest, 16, &expected),
        "{}",
        report(&digest, 16, &expected)
    );
    let check_ms = started.elapsed().as_millis();
    let measured = inventory(&digest, 16, &expected);
    assert_eq!(measured.columns, Q_ADVICE_COLUMNS);
    // One compression from witnessed message words (the generic block; the
    // sixteen word range checks are counted separately).
    let (message, block_digest) = fips_vectors()[0];
    let block = ShaCircuit::<Fq>::new(Mode::Message(message.to_vec())).q_shaped();
    let block_measured = inventory(&block, 16, &block_digest);
    let word_checks_rows = 16 * 2;
    let word_check_cells = 16 * 16;
    let compress_rows = block_measured.rows - word_checks_rows;
    let compress_cells = block_measured.cells - word_check_cells;
    let codec_and_block_rows = measured.rows;
    let (cs, _) = configure(&digest).expect("configured");
    let gate_polys: usize = cs.gates().iter().map(|gate| gate.polynomials().len()).sum();
    let gate_nodes: usize = cs
        .gates()
        .iter()
        .flat_map(|gate| gate.polynomials().iter().map(Expression::node_count))
        .sum();
    println!(
        "G3_3 measured k=16 advice_columns={} sha_columns={} fixed_columns={} \
         selectors={} equality_columns={} table_rows={} \
         hash_digest_rows={} hash_digest_cells={} codec_rows={} \
         compress_rows={} compress_cells={} degree={} lookups={} \
         advice_queries={} fixed_queries={} gates={} gate_polys={} gate_nodes={} \
         check_ms={check_ms}",
        measured.columns,
        SHA256_ADVICE_COLUMNS,
        cs.num_fixed_columns(),
        cs.num_selectors(),
        cs.permutation().columns().len(),
        TABLE_ROWS,
        codec_and_block_rows,
        measured.cells,
        DIGEST_CODEC_ROWS,
        compress_rows,
        compress_cells,
        cs.degree(),
        cs.lookups().len(),
        cs.advice_queries().len(),
        cs.fixed_queries().len(),
        cs.gates().len(),
        gate_polys,
        gate_nodes,
    );
    assert!(codec_and_block_rows <= G3_3_MAX_ROWS);
    assert!(measured.cells <= G3_3_MAX_CELLS);
    assert!(compress_rows <= G3_3_MAX_ROWS);
    assert!(compress_cells <= G3_3_MAX_CELLS);
    assert!(cs.degree() <= MAX_GATE_DEGREE);
    assert_eq!(codec_and_block_rows, 2_094);
    assert_eq!(codec_and_block_rows, HASH_DIGEST_ROWS);
}

/// Keys, a proof and verification of `circuit` on Pallas at `k`; returns
/// the proof length.
fn round_trip(
    circuit: &ShaCircuit<Fq>,
    k: u32,
    digest: &[u8; 32],
    transcript: TranscriptV1,
) -> usize {
    let public = public::<Fq>(digest);
    let params = PinnedParams::<Ep>::derive(k).expect("params");
    let mut config = KeygenConfig::new(transcript);
    if transcript == TranscriptV1::KagemushaPoseidonRp57 {
        config.instance_mode = InstanceModeV1::Direct;
        config.proof_suffix = ProofSuffixV1::FoldedGenerator;
    }
    let started = Instant::now();
    let pk = keygen_pk(&params, &circuit.without_witnesses(), &config).expect("proving key");
    let keygen_ms = started.elapsed().as_millis();
    let prove = |seed: u8, public: &[Fq]| {
        let randomness = ProverRandomness::recovery(move |_context: &[u8; 32]| {
            Ok::<_, Infallible>(ChaCha20Rng::from_seed([seed; 32]))
        });
        prove_circuit(
            &params,
            &pk,
            circuit,
            &[public.to_vec()],
            randomness,
            ProverConfig::default(),
        )
    };
    let started = Instant::now();
    let proof = prove(7, &public).expect("proof");
    let prove_ms = started.elapsed().as_millis();
    let verify = |public: &[Fq], proof: &[u8]| {
        verify_full(
            &params,
            pk.binding(),
            pk.vk(),
            &[public.to_vec()],
            proof,
            MemoryBudget::DEFAULT,
        )
    };
    let started = Instant::now();
    assert_eq!(verify(&public, &proof), Ok(()));
    let verify_ms = started.elapsed().as_millis();
    println!(
        "SHA256_PROOF curve=pallas k={k} transcript={transcript:?} bytes={} keygen_ms={keygen_ms} \
         prove_ms={prove_ms} verify_ms={verify_ms}",
        proof.len()
    );
    let mut wrong = public.clone();
    wrong[0] += Fq::ONE;
    assert!(verify(&wrong, &proof).is_err(), "wrong digest");
    let mut corrupted = proof.clone();
    let middle = corrupted.len() / 2;
    corrupted[middle] ^= 1;
    assert!(verify(&public, &corrupted).is_err(), "corrupted proof");
    // A witness for a wrong digest yields no accepted proof.
    if let Ok(bad) = prove(7, &wrong) {
        assert!(verify(&wrong, &bad).is_err(), "wrong-digest proof");
    }
    proof.len()
}

#[test]
#[ignore = "k = 12 Pallas proofs of one SHA-256 block; run in release"]
fn sha256_real_pallas_proofs_of_poseidon_digest() {
    let m = hash_with_domain::<Fp>(u64::from_le_bytes(*b"kgwsign1"), &[Fp::from(5_u64)]);
    let expected: [u8; 32] = Sha256::digest(m.to_repr()).into();
    let circuit = ShaCircuit::<Fq>::new(Mode::Digest {
        digest: as_field(&m),
        fp: true,
    });
    let poseidon = round_trip(&circuit, 12, &expected, TranscriptV1::KagemushaPoseidonRp57);
    let blake = round_trip(&circuit, 12, &expected, TranscriptV1::Blake2bChallenge255);
    println!("sha256 digest proof bytes: poseidon/direct {poseidon}, blake2b {blake}");
}

#[test]
#[ignore = "k = 16 Pallas proof at the Q-leaf width; run in release"]
fn sha256_real_pallas_proof_at_the_q_shape() {
    let m = hash_with_domain::<Fp>(u64::from_le_bytes(*b"kgwsign1"), &[Fp::from(6_u64)]);
    let expected: [u8; 32] = Sha256::digest(m.to_repr()).into();
    let circuit = ShaCircuit::<Fq>::new(Mode::Digest {
        digest: as_field(&m),
        fp: true,
    })
    .q_shaped();
    round_trip(&circuit, 16, &expected, TranscriptV1::KagemushaPoseidonRp57);
}
