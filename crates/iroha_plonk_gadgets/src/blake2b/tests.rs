//! Independent digest vectors, exact layout accounting and hostile witnesses.

use ff::{Field, PrimeField};
use iroha_pasta::{Fp, Fq, PastaField};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Circuit, Error, Layouter, SimpleFloorPlanner, Value, synthesize},
};

use super::*;
use crate::{
    GlueChip, GlueConfig,
    tamper::{Tamper, assigned_advice_cells, check_tampered, check_tampers, undetected_tampers},
};

#[derive(Clone, Debug)]
struct Config {
    blake: Blake2bConfig,
    glue: GlueConfig,
    public: Column<Instance>,
}

fn configure<F: PastaField>(meta: &mut ConstraintSystem<F>, public_len: usize) -> Config {
    let advice = core::array::from_fn(|_| meta.advice_column());
    let constants = meta.fixed_column();
    let blake = Blake2bConfig::configure(meta, advice, constants);
    let advice = core::array::from_fn(|_| meta.advice_column());
    let glue = GlueConfig::configure(meta, advice, constants);
    let public = meta.instance_column(public_len);
    meta.enable_equality(public);
    Config {
        blake,
        glue,
        public,
    }
}

fn witness<F: PastaField>(known: bool, value: F) -> Value<F> {
    if known {
        Value::known(value)
    } else {
        Value::unknown()
    }
}

#[derive(Clone)]
struct HashCircuit<F: PastaField> {
    input: Vec<F>,
    marked: bool,
    known: bool,
}

impl<F: PastaField> Circuit<F> for HashCircuit<F> {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = usize;

    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }

    fn params(&self) -> usize {
        self.input.len()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Config {
        configure(meta, 32)
    }

    fn configure_with_params(meta: &mut ConstraintSystem<F>, input_len: usize) -> Config {
        configure(meta, input_len + 32)
    }

    fn synthesize(&self, config: Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        let mut chip = Blake2bChip::new(&config.blake);
        let mut glue = GlueChip::new(config.glue);
        let cells = layouter.assign_region(
            || "blake2b hash",
            |mut region| {
                let values: Vec<_> = self
                    .input
                    .iter()
                    .map(|value| witness(self.known, *value))
                    .collect();
                let mut inputs = glue.witnesses(&mut region, &values)?;
                let digest = if self.marked {
                    chip.hash_marked(&mut region, &inputs)?
                } else {
                    chip.hash(&mut region, &inputs)?
                };
                let blocks = inputs.len().div_ceil(128).max(1);
                assert_eq!(
                    chip.next_row(),
                    2 + inputs.len() + BLAKE2B_COMPRESSION_ROWS * blocks + 32
                );
                inputs.extend_from_slice(digest.bytes());
                Ok(inputs)
            },
        )?;
        for (index, word) in cells.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.public, index)?;
        }
        Ok(())
    }
}

fn decode_hex(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII hex"), 16)
                .expect("hex byte")
        })
        .collect()
}

fn hash_case<F: PastaField>(
    input: &[u8],
    expected: &str,
    marked: bool,
) -> (HashCircuit<F>, Vec<F>, u32) {
    let input: Vec<_> = input.iter().map(|byte| F::from(u64::from(*byte))).collect();
    let mut digest = decode_hex(expected);
    if marked {
        digest[31] |= 1;
    }
    let mut public = input.clone();
    public.extend(digest.iter().map(|byte| F::from(u64::from(*byte))));
    let rows = 2 + input.len() + BLAKE2B_COMPRESSION_ROWS * input.len().div_ceil(128).max(1) + 32;
    let k = (rows + 64).next_power_of_two().ilog2();
    (
        HashCircuit {
            input,
            marked,
            known: true,
        },
        public,
        k,
    )
}

const EMPTY: &str = "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8";
const ABC: &str = "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319";

#[test]
fn raw_digest_vectors_cover_empty_partial_full_and_multiple_blocks() {
    // Independent oracle: Python hashlib.blake2b(message, digest_size=32).
    // Numbered cases contain bytes(i % 256 for i in range(n)). These test the
    // counter, final flag, zero padding, little-endian codec and parameter word.
    let vectors = [
        (0, EMPTY),
        (
            1,
            "03170a2e7597b7b7e3d84c05391d139a62b157e78786d8c082f29dcf4c111314",
        ),
        (
            127,
            "f2fe67ff342e21b8f45e8f2e0bcd1d9243245d50ee6c78042e9c491388791c72",
        ),
        (
            128,
            "c3582f71ebb2be66fa5dd750f80baae97554f3b015663c8be377cfcb2488c1d1",
        ),
        (
            129,
            "f7f3c46ba2564ff4c4c162da1f5b605f9f1c4aa6a20652a9f9a337c1a2f5b9c9",
        ),
        (
            255,
            "1d0850ee9bca0abc9601e9deabe1418fedec2fb6ac4150bd5302d2430f9be943",
        ),
        (
            256,
            "39a7eb9fedc19aabc83425c6755dd90e6f9d0c804964a1f4aaeea3b9fb599835",
        ),
        (
            257,
            "45f7f084c30bac7cbae2e1963bc6e6b0d8cb227a12927e97fb941d288fb1f9a3",
        ),
    ];
    for (len, expected) in vectors {
        let input: Vec<_> = (0..len)
            .map(|i| u8::try_from(i % 256).expect("byte residue"))
            .collect();
        let (circuit, public, k) = hash_case::<Fp>(&input, expected, false);
        assert!(
            check_circuit(&circuit, k, &[public], CheckMode::Strict)
                .expect("layout")
                .is_satisfied(),
            "length {len}"
        );
    }
    let (circuit, public, k) = hash_case::<Fp>(
        &[255; 128],
        "d3f35cd80b65c482e3026da32b729e9e7fd75065aca6677b16e488a58f5625f7",
        false,
    );
    assert!(
        check_circuit(&circuit, k, &[public], CheckMode::Strict)
            .expect("all ones")
            .is_satisfied()
    );
}

#[test]
fn both_fields_and_native_marker_match_digest_bytes() {
    fn exercise<F: PastaField>() {
        // Empty's last byte is even; abc's is odd. Both marker branches must
        // preserve all other bits and the message/digest instance linkage.
        for (input, expected) in [(b"".as_slice(), EMPTY), (b"abc".as_slice(), ABC)] {
            for marked in [false, true] {
                let (circuit, public, k) = hash_case::<F>(input, expected, marked);
                assert!(
                    check_circuit(&circuit, k, &[public], CheckMode::Strict)
                        .expect("layout")
                        .is_satisfied()
                );
            }
        }
    }
    exercise::<Fp>();
    exercise::<Fq>();
}

#[test]
fn hash_layout_counts_degree_and_unknown_witness_shape_are_pinned() {
    let (circuit, public, k) = hash_case::<Fp>(b"abc", ABC, false);
    let known = synthesize(&circuit, k, Some(core::slice::from_ref(&public))).expect("known");
    let unknown = synthesize(&circuit.without_witnesses(), k, None).expect("unknown");
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(known.tables.selectors(), unknown.tables.selectors());
    assert_eq!(known.tables.permutation(), unknown.tables.permutation());
    // Four glue columns are outside the chip's fourteen-column inventory.
    let count = known.tables.advice_assigned()[..BLAKE2B_ADVICE_COLUMNS]
        .iter()
        .flatten()
        .filter(|assigned| **assigned)
        .count();
    assert_eq!(count, 2 + 9 * (3 + 32) + BLAKE2B_COMPRESSION_CELLS);
    let (cs, _) = iroha_plonk::frontend::configure(&circuit).expect("config");
    assert!(cs.degree() <= crate::MAX_GATE_DEGREE);
    // Check this chip's gates separately: the glue chip may raise degree.
    let mut meta = ConstraintSystem::<Fp>::default();
    let columns = core::array::from_fn(|_| meta.advice_column());
    let constants = meta.fixed_column();
    Blake2bConfig::configure(&mut meta, columns, constants);
    assert_eq!(meta.degree(), 3);
}

#[test]
fn hash_rejects_nonbytes_changed_public_input_and_changed_digest() {
    let (circuit, public, k) = hash_case::<Fp>(b"abc", ABC, false);
    for index in [0, 2, 3, 34] {
        let mut wrong = public.clone();
        wrong[index] += Fp::ONE;
        assert!(
            !check_circuit(&circuit, k, &[wrong], CheckMode::Strict)
                .expect("public tamper")
                .is_satisfied()
        );
    }
    let (mut circuit, mut public, k) = hash_case::<Fp>(
        &[0],
        "03170a2e7597b7b7e3d84c05391d139a62b157e78786d8c082f29dcf4c111314",
        false,
    );
    // The low eight bits still describe zero; changing both the external cell
    // and its instance must nevertheless fail the byte decomposition.
    for invalid in [Fp::from(256), -Fp::ONE] {
        circuit.input[0] = invalid;
        public[0] = invalid;
        assert!(
            !check_circuit(
                &circuit,
                k,
                core::slice::from_ref(&public),
                CheckMode::Strict
            )
            .expect("nonbyte")
            .is_satisfied()
        );
    }
    let (circuit, mut public, k) = hash_case::<Fp>(&[], EMPTY, true);
    public[31] -= Fp::ONE;
    assert!(
        !check_circuit(&circuit, k, &[public], CheckMode::Strict)
            .expect("removed marker")
            .is_satisfied()
    );
}

#[test]
fn hash_tampers_cover_constants_counter_final_flag_rounds_feedforward_and_digest() {
    let (circuit, public, k) = hash_case::<Fp>(b"abc", ABC, false);
    let start = 2 + 3;
    let feedforward = start + 48 + 12 * 8 * 160;
    let output = start + BLAKE2B_COMPRESSION_ROWS;
    for (column, row) in [
        (0, 0),
        (0, 1), // zero, one: also parameter-block and padding sources
        (1, 2), // input decomposition
        (8, start),
        (8, start + 16),
        (8, start + 32), // both counter limbs, final flag
        (13, start + 48),
        (13, start + 48 + 15),          // low and top carry
        (8, start + 48 + 32),           // XOR before rotation
        (8, start + 48 + 11 * 8 * 160), // final round
        (8, feedforward),
        (0, output),
        (8, output + 31),
    ] {
        let tamper = Tamper {
            column,
            row,
            delta: Fp::ONE,
        };
        assert!(
            !check_tampered(&circuit, k, core::slice::from_ref(&public), Some(tamper))
                .expect("assigned cell")
                .is_satisfied(),
            "{column}:{row}"
        );
    }
}

#[derive(Clone, Copy)]
enum Primitive {
    Add,
    XorRotate(usize),
}

#[derive(Clone)]
struct PrimitiveCircuit<F: PastaField> {
    a: u64,
    b: u64,
    operation: Primitive,
    known: bool,
    marker: core::marker::PhantomData<F>,
}

impl<F: PastaField> Circuit<F> for PrimitiveCircuit<F> {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<F>) -> Config {
        configure(meta, 24)
    }
    fn synthesize(&self, config: Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        let mut chip = Blake2bChip::new(&config.blake);
        let mut glue = GlueChip::new(config.glue);
        let output = layouter.assign_region(
            || "blake2b primitive",
            |mut region| {
                let constants = chip.constants(&mut region)?;
                let values: Vec<_> = self
                    .a
                    .to_le_bytes()
                    .into_iter()
                    .chain(self.b.to_le_bytes())
                    .map(|byte| witness(self.known, F::from(u64::from(byte))))
                    .collect();
                let mut inputs = glue.witnesses(&mut region, &values)?;
                let bytes = inputs
                    .iter()
                    .map(|word| chip.input_byte(&mut region, word))
                    .collect::<Result<Vec<_>, _>>()?;
                let a = Bits64(core::array::from_fn(|i| bytes[i / 8][i % 8].clone()));
                let b = Bits64(core::array::from_fn(|i| bytes[8 + i / 8][i % 8].clone()));
                let result = match self.operation {
                    Primitive::Add => chip.add(&mut region, &a, &b, &constants[0])?,
                    Primitive::XorRotate(rotation) => {
                        chip.xor(&mut region, &a, &b)?.rotate_right(rotation)
                    }
                };
                for byte in 0..8 {
                    let bits = core::array::from_fn(|bit| result.0[byte * 8 + bit].clone());
                    inputs.push(chip.output_byte(&mut region, &bits)?);
                }
                assert_eq!(chip.next_row(), 42);
                Ok(inputs)
            },
        )?;
        for (i, word) in output.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.public, i)?;
        }
        Ok(())
    }
}

fn primitive_case<F: PastaField>(
    a: u64,
    b: u64,
    operation: Primitive,
) -> (PrimitiveCircuit<F>, Vec<F>) {
    let expected = match operation {
        Primitive::Add => a.wrapping_add(b),
        Primitive::XorRotate(rotation) => {
            (a ^ b).rotate_right(u32::try_from(rotation % 64).expect("rotation modulo word width"))
        }
    };
    let public = a
        .to_le_bytes()
        .into_iter()
        .chain(b.to_le_bytes())
        .chain(expected.to_le_bytes())
        .map(|byte| F::from(u64::from(byte)))
        .collect();
    (
        PrimitiveCircuit {
            a,
            b,
            operation,
            known: true,
            marker: core::marker::PhantomData,
        },
        public,
    )
}

#[test]
fn every_primitive_cell_is_pinned_and_all_rotations_match_native() {
    fn exercise<F: PastaField>() {
        for operation in [Primitive::Add, Primitive::XorRotate(63)] {
            let (circuit, public) = primitive_case::<F>(u64::MAX, 0x7654_3210_fedc_ba98, operation);
            let cells =
                assigned_advice_cells(&circuit, 6, core::slice::from_ref(&public)).expect("cells");
            let chip_cells = cells
                .iter()
                .filter(|(column, _)| *column < BLAKE2B_ADVICE_COLUMNS)
                .count();
            assert_eq!(
                chip_cells,
                2 + 9 * 24
                    + match operation {
                        Primitive::Add => 224,
                        Primitive::XorRotate(_) => 192,
                    }
            );
            assert!(
                undetected_tampers(&circuit, 6, &[public])
                    .expect("tamper sweep")
                    .is_empty()
            );
        }
        for (a, b) in [
            (0, 0),
            (0, u64::MAX),
            (u64::MAX, u64::MAX),
            (0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210),
        ] {
            for rotation in [16, 24, 32, 63] {
                let (circuit, public) = primitive_case::<F>(a, b, Primitive::XorRotate(rotation));
                assert!(
                    check_circuit(&circuit, 6, &[public], CheckMode::Strict)
                        .expect("rotate")
                        .is_satisfied()
                );
            }
            let (circuit, public) = primitive_case::<F>(a, b, Primitive::Add);
            assert!(
                check_circuit(&circuit, 6, &[public], CheckMode::Strict)
                    .expect("carry boundary")
                    .is_satisfied()
            );
        }
    }
    exercise::<Fp>();
    exercise::<Fq>();
}

#[test]
fn coordinated_nonboolean_sum_and_carry_cannot_preserve_addition() {
    let (circuit, public) = primitive_case::<Fp>(0, 0, Primitive::Add);
    // Both changes cancel in a+b+cin-out-16*cout, so boolean constraints are
    // essential even when an attacker supplies a coordinated forged witness.
    let tampers = [
        Tamper {
            column: 8,
            row: 18,
            delta: Fp::from(16),
        },
        Tamper {
            column: 13,
            row: 18,
            delta: -Fp::ONE,
        },
    ];
    assert!(
        !check_tampers(&circuit, 6, &[public], &tampers)
            .expect("coordinated tamper")
            .is_satisfied()
    );
}

#[test]
fn bounded_cursor_uses_the_requested_start() {
    let mut meta = ConstraintSystem::<Fp>::default();
    let columns = core::array::from_fn(|_| meta.advice_column());
    let constants = meta.fixed_column();
    let config = Blake2bConfig::configure(&mut meta, columns, constants);
    let chip = Blake2bChip::<Fp>::with_rows(&config, RowCursor::bounded(7, 8));
    assert_eq!(chip.next_row(), 7);
}

#[derive(Clone)]
struct WordCodecCircuit<F: PastaField> {
    value: F,
}

impl<F: PastaField> Circuit<F> for WordCodecCircuit<F> {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        self.clone()
    }
    fn configure(meta: &mut ConstraintSystem<F>) -> Config {
        configure(meta, 2)
    }
    fn synthesize(&self, config: Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        let mut chip = Blake2bChip::new(&config.blake);
        let mut glue = GlueChip::new(config.glue);
        let words = layouter.assign_region(
            || "blake2b u64 codec",
            |mut region| {
                let input = glue.witness(&mut region, Value::known(self.value))?;
                let bits = chip.input_word(&mut region, &input)?;
                let output = chip.output_word(&mut region, &bits)?;
                assert_eq!(chip.next_row(), 18);
                Ok([input, output.word().clone()])
            },
        )?;
        for (i, word) in words.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.public, i)?;
        }
        Ok(())
    }
}

#[test]
fn streaming_word_codec_checks_every_cell_and_rejects_non_u64_values() {
    fn exercise<F: PastaField>() {
        let circuit = WordCodecCircuit {
            value: F::from(u64::MAX),
        };
        assert!(
            undetected_tampers(&circuit, 5, &[vec![circuit.value; 2]])
                .expect("word codec sweep")
                .is_empty()
        );
        for invalid in [F::from_u128(1_u128 << 64), -F::ONE] {
            let circuit = WordCodecCircuit { value: invalid };
            assert!(
                !check_circuit(&circuit, 5, &[vec![invalid; 2]], CheckMode::Strict)
                    .expect("non-u64")
                    .is_satisfied()
            );
        }
    }
    exercise::<Fp>();
    exercise::<Fq>();
}

/// Integer-only RFC compression oracle. Its machine-word operations do not
/// use the circuit's bit or carry witnesses; complete hashes also have the
/// independent hashlib vectors above.
fn native_compress(mut h: [u64; 8], block: &[u8; 128], counter: u128, last: bool) -> [u64; 8] {
    fn g(state: &mut [u64; 16], [first, second, third, fourth]: [usize; 4], left: u64, right: u64) {
        state[first] = state[first].wrapping_add(state[second]).wrapping_add(left);
        state[fourth] = (state[fourth] ^ state[first]).rotate_right(32);
        state[third] = state[third].wrapping_add(state[fourth]);
        state[second] = (state[second] ^ state[third]).rotate_right(24);
        state[first] = state[first].wrapping_add(state[second]).wrapping_add(right);
        state[fourth] = (state[fourth] ^ state[first]).rotate_right(16);
        state[third] = state[third].wrapping_add(state[fourth]);
        state[second] = (state[second] ^ state[third]).rotate_right(63);
    }
    let message: [u64; 16] = core::array::from_fn(|i| {
        u64::from_le_bytes(block[i * 8..i * 8 + 8].try_into().expect("word"))
    });
    let mut v = [0; 16];
    v[..8].copy_from_slice(&h);
    v[8..].copy_from_slice(&IV);
    v[12] ^= u64::from_le_bytes(
        counter.to_le_bytes()[..8]
            .try_into()
            .expect("low counter word"),
    );
    v[13] ^= u64::try_from(counter >> 64).expect("high counter word");
    if last {
        v[14] = !v[14];
    }
    for r in 0..12 {
        let s = SIGMA[r % 10];
        g(&mut v, [0, 4, 8, 12], message[s[0]], message[s[1]]);
        g(&mut v, [1, 5, 9, 13], message[s[2]], message[s[3]]);
        g(&mut v, [2, 6, 10, 14], message[s[4]], message[s[5]]);
        g(&mut v, [3, 7, 11, 15], message[s[6]], message[s[7]]);
        g(&mut v, [0, 5, 10, 15], message[s[8]], message[s[9]]);
        g(&mut v, [1, 6, 11, 12], message[s[10]], message[s[11]]);
        g(&mut v, [2, 7, 8, 13], message[s[12]], message[s[13]]);
        g(&mut v, [3, 4, 9, 14], message[s[14]], message[s[15]]);
    }
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
    h
}

#[derive(Clone)]
struct StreamCircuit<F: PastaField> {
    state: [F; 8],
    block: [F; 128],
    counter: [F; 2],
    last: F,
    initial: bool,
    known: bool,
}

impl<F: PastaField> Circuit<F> for StreamCircuit<F> {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<F>) -> Config {
        configure(meta, 179)
    }
    fn synthesize(&self, config: Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        let mut chip = Blake2bChip::new(&config.blake);
        let mut glue = GlueChip::new(config.glue);
        let words = layouter.assign_region(
            || "blake2b streaming compression",
            |mut region| {
                let values: Vec<_> = self
                    .state
                    .into_iter()
                    .chain(self.block)
                    .chain(self.counter)
                    .chain([self.last])
                    .map(|value| witness(self.known, value))
                    .collect();
                let mut words = glue.witnesses(&mut region, &values)?;
                let state_words = words[..8]
                    .to_vec()
                    .try_into()
                    .map_err(|_| Error::Synthesis)?;
                let state = chip.state_from_words(&mut region, &state_words)?;
                if self.initial {
                    let initial = chip.initial_state(&mut region)?;
                    let initial = chip.state_words(&mut region, &initial)?;
                    for (given, expected) in state_words.iter().zip(&initial) {
                        GlueChip::assert_equal(&mut region, given, expected.word())?;
                    }
                }
                let block = words[8..136]
                    .to_vec()
                    .try_into()
                    .map_err(|_| Error::Synthesis)?;
                let counter = words[136..138]
                    .to_vec()
                    .try_into()
                    .map_err(|_| Error::Synthesis)?;
                let last = glue.assert_bool(&mut region, &words[138])?;
                let state = chip.compress_block(&mut region, &state, &block, &counter, &last)?;
                let result = chip.state_words(&mut region, &state)?;
                words.extend(result.iter().map(|word| word.word().clone()));
                // A continuation imports precisely the exported cells, testing
                // all eight words across the interface rather than a host value.
                let exports = result.map(|word| word.word().clone());
                let restored = chip.state_from_words(&mut region, &exports)?;
                let digest = chip.digest(&mut region, &restored)?;
                words.extend_from_slice(digest.bytes());
                assert_eq!(
                    chip.next_row(),
                    72 + if self.initial { 72 } else { 0 } + 2 + 15_810 + 72 + 72 + 32
                );
                Ok(words)
            },
        )?;
        for (i, word) in words.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.public, i)?;
        }
        Ok(())
    }
}

fn stream_case<F: PastaField>(
    state: [u64; 8],
    block: [u8; 128],
    counter: u128,
    last: bool,
    initial: bool,
) -> (StreamCircuit<F>, Vec<F>) {
    let output = native_compress(state, &block, counter, last);
    let circuit = StreamCircuit {
        state: state.map(F::from),
        block: block.map(|byte| F::from(u64::from(byte))),
        counter: [
            F::from(u64::from_le_bytes(
                counter.to_le_bytes()[..8]
                    .try_into()
                    .expect("low counter word"),
            )),
            F::from(u64::try_from(counter >> 64).expect("high counter word")),
        ],
        last: F::from(u64::from(last)),
        initial,
        known: true,
    };
    let mut public: Vec<_> = circuit
        .state
        .into_iter()
        .chain(circuit.block)
        .chain(circuit.counter)
        .chain([circuit.last])
        .collect();
    public.extend(output.map(F::from));
    public.extend(
        output[..4]
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .map(|byte| F::from(u64::from(byte))),
    );
    (circuit, public)
}

#[test]
fn streaming_compression_binds_high_counter_final_bit_and_full_state() {
    let initial = core::array::from_fn(|i| IV[i] ^ if i == 0 { 0x0101_0020 } else { 0 });
    let block = core::array::from_fn(|i| u8::try_from(i).expect("fixture byte index"));
    for (counter, last) in [
        (128, true),
        ((1_u128 << 64) + 129, false),
        (u128::MAX, true),
    ] {
        let (circuit, public) = stream_case::<Fp>(initial, block, counter, last, true);
        assert!(
            check_circuit(
                &circuit,
                14,
                core::slice::from_ref(&public),
                CheckMode::Strict
            )
            .expect("stream")
            .is_satisfied()
        );
        if counter == 128 {
            let expected =
                decode_hex("c3582f71ebb2be66fa5dd750f80baae97554f3b015663c8be377cfcb2488c1d1");
            assert_eq!(
                &public[147..],
                &expected
                    .into_iter()
                    .map(|byte| Fp::from(u64::from(byte)))
                    .collect::<Vec<_>>()
            );
        }
    }
    // A continuation is allowed an imported non-IV state, with all eight
    // words bound to public input and all eight output words checked.
    let first = native_compress(initial, &block, 128, false);
    let (circuit, public) = stream_case::<Fq>(first, block, 256, true, false);
    assert!(
        check_circuit(&circuit, 14, &[public], CheckMode::Strict)
            .expect("continuation")
            .is_satisfied()
    );
}

#[test]
fn streaming_counter_and_flag_tampering_and_noncanonical_words_fail() {
    let initial = core::array::from_fn(|i| IV[i] ^ if i == 0 { 0x0101_0020 } else { 0 });
    let (circuit, public) = stream_case::<Fp>(initial, [0; 128], 0, true, true);
    for index in [0, 7, 136, 137, 138, 139, 146, 178] {
        let mut changed = public.clone();
        changed[index] += Fp::ONE;
        assert!(
            !check_circuit(&circuit, 14, &[changed], CheckMode::Strict)
                .expect("stream public tamper")
                .is_satisfied()
        );
    }
    for (index, invalid) in [
        (136, Fp::from_u128(1_u128 << 64)),
        (137, -Fp::ONE),
        (138, Fp::from(2)),
    ] {
        let mut forged = circuit.clone();
        let mut changed = public.clone();
        changed[index] = invalid;
        if index == 138 {
            forged.last = invalid;
        } else {
            forged.counter[index - 136] = invalid;
        }
        assert!(
            !check_circuit(&forged, 14, &[changed], CheckMode::Strict)
                .expect("invalid counter or flag")
                .is_satisfied()
        );
    }
    let known =
        synthesize(&circuit, 14, Some(core::slice::from_ref(&public))).expect("stream known");
    let unknown = synthesize(&circuit.without_witnesses(), 14, None).expect("stream unknown");
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(known.tables.selectors(), unknown.tables.selectors());
    assert_eq!(known.tables.permutation(), unknown.tables.permutation());
}
