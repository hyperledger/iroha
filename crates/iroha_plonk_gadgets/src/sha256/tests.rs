//! Adversarial and tamper tests of the SHA-256 chip units (crate-internal:
//! they drive units with forged witnesses through the chip's test hooks).

use ff::{Field, PrimeField};
use iroha_pasta::{Fp, Fq, PastaField};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::{Advice, Column, ConstraintSystem},
    frontend::{Circuit, Error, Layouter, SimpleFloorPlanner, Value},
};

use super::{
    chip::{SHA256_ADVICE_COLUMNS, Sha256Chip, Sha256Config, Sha256State, Sha256Word},
    native::{
        SHA256_IV, canonical_u32_limbs, compress, digest_block, digest_message, sha256_of_digest,
        spread, state_bytes,
    },
    spec::{DECOMPOSE_A, DECOMPOSE_E, DECOMPOSE_W, HALF, SPECS},
};
use crate::{
    GlueChip,
    arith::GlueConfig,
    cells::low_u128,
    tamper::{Tamper, assigned_advice_cells, check_tampered},
};

/// The smallest `k` whose usable rows hold the spread table.
const K: u32 = 12;

/// What a test circuit lays out.
#[derive(Clone, Debug)]
enum Program<F> {
    /// `hash_digest` of `digest` (as a value of `Fp` when `fp`, else `Fq`),
    /// with the codec bytes forged when `forged` is set.
    Digest {
        digest: F,
        fp: bool,
        forged: Option<[u8; 32]>,
    },
    /// A compression of `block` from `state`; `None` words are constants of
    /// the standard values, `Some` words are witnessed.
    Compress {
        state: [u32; 8],
        assigned_state: bool,
        block: [u32; 16],
        constant_tail: bool,
    },
    /// One split of the witness `input` with explicit halves.
    Split { halves: (u32, u32), input: u64 },
    /// One decomposition unit of `value`.
    Decompose { spec: usize, value: u32 },
    /// A 32-bit range check of the witness `value`.
    RangeCheck { value: u64 },
}

#[derive(Clone, Debug)]
struct TestCircuit<F> {
    program: Program<F>,
    known: bool,
}

impl<F> TestCircuit<F> {
    const fn new(program: Program<F>) -> Self {
        Self {
            program,
            known: true,
        }
    }
}

fn value<V: Copy>(known: bool, value: V) -> Value<V> {
    if known {
        Value::known(value)
    } else {
        Value::unknown()
    }
}

impl<F: PastaField> Circuit<F> for TestCircuit<F> {
    type Config = (Sha256Config, GlueConfig);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let advice: [Column<Advice>; SHA256_ADVICE_COLUMNS] =
            core::array::from_fn(|_| meta.advice_column());
        let constants = meta.fixed_column();
        let sha = Sha256Config::configure(meta, advice, constants);
        let glue_advice = core::array::from_fn(|_| meta.advice_column());
        let glue = GlueConfig::configure(meta, glue_advice, constants);
        (sha, glue)
    }

    fn synthesize(
        &self,
        (sha, glue): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let mut chip = Sha256Chip::new(&sha);
        let mut glue = GlueChip::new(glue);
        chip.load_table(&mut layouter)?;
        let known = self.known;
        layouter.assign_region(
            || "sha256 test",
            |mut region| match &self.program {
                Program::Digest { digest, fp, forged } => {
                    let word = glue.witness(&mut region, value(known, *digest))?;
                    let block = if let Some(bytes) = forged {
                        let modulus = if *fp {
                            canonical_u32_limbs(&-Fp::ONE)
                        } else {
                            canonical_u32_limbs(&-Fq::ONE)
                        };
                        chip.digest_block_with_bytes(
                            &mut region,
                            &word,
                            &modulus,
                            value(known, *bytes),
                        )?
                    } else if *fp {
                        chip.digest_block::<Fp>(&mut region, &word)?
                    } else {
                        chip.digest_block::<Fq>(&mut region, &word)?
                    };
                    let out = chip.compress(&mut region, &Sha256State::iv(), &block)?;
                    // Native parity of the honest path.
                    if forged.is_none() {
                        let expected = if *fp {
                            Fp::from_repr(digest.to_repr())
                                .into_option()
                                .map(|m| sha256_of_digest(&m))
                        } else {
                            Fq::from_repr(digest.to_repr())
                                .into_option()
                                .map(|m| sha256_of_digest(&m))
                        };
                        let mut mismatch = false;
                        let _ = out.value().map(|bytes| mismatch = Some(bytes) != expected);
                        if mismatch {
                            return Err(Error::Synthesis);
                        }
                    }
                    Ok(())
                }
                Program::Compress {
                    state,
                    assigned_state,
                    block,
                    constant_tail,
                } => {
                    let mut state_words = Vec::new();
                    for word in state {
                        state_words.push(if *assigned_state {
                            Sha256Word::Assigned(chip.assign_u32(&mut region, value(known, *word))?)
                        } else {
                            Sha256Word::Constant(*word)
                        });
                    }
                    let mut block_words = Vec::new();
                    for (index, word) in block.iter().enumerate() {
                        block_words.push(if *constant_tail && index >= 8 {
                            Sha256Word::Constant(*word)
                        } else {
                            Sha256Word::Assigned(chip.assign_u32(&mut region, value(known, *word))?)
                        });
                    }
                    let state_words: [Sha256Word<F>; 8] =
                        state_words.try_into().map_err(|_| Error::Synthesis)?;
                    let block_words: [Sha256Word<F>; 16] =
                        block_words.try_into().map_err(|_| Error::Synthesis)?;
                    let before = chip.next_row();
                    let rows = Sha256Chip::compress_rows(
                        &Sha256State::new(state_words.clone()),
                        &block_words,
                    );
                    let out =
                        chip.compress(&mut region, &Sha256State::new(state_words), &block_words)?;
                    if chip.next_row() - before != rows {
                        return Err(Error::Synthesis);
                    }
                    let mut mismatch = false;
                    let _ = out.value().map(|bytes| {
                        mismatch = bytes != state_bytes(&compress(state, block));
                    });
                    if mismatch {
                        return Err(Error::Synthesis);
                    }
                    Ok(())
                }
                Program::Split { halves, input } => {
                    let input = glue.witness(&mut region, value(known, F::from(*input)))?;
                    chip.test_split(&mut region, value(known, *halves), &input)?;
                    Ok(())
                }
                Program::Decompose { spec, value: word } => {
                    let spec = SPECS.get(*spec).ok_or(Error::Synthesis)?;
                    chip.test_decompose(&mut region, spec, value(known, *word))?;
                    Ok(())
                }
                Program::RangeCheck { value: word } => {
                    let input = glue.witness(&mut region, value(known, F::from(*word)))?;
                    let checked = chip.range_check_u32(&mut region, &input)?;
                    if chip.next_row() != 2
                        || chip.config().advice_columns()[0] != sha.advice_columns()[0]
                    {
                        return Err(Error::Synthesis);
                    }
                    let mut mismatch = false;
                    let _ = checked
                        .value()
                        .map(|checked| mismatch = u128::from(*word) != checked);
                    if mismatch && *word < 1 << 32 {
                        return Err(Error::Synthesis);
                    }
                    Ok(())
                }
            },
        )
    }
}

fn satisfied<F: PastaField>(program: Program<F>) -> bool {
    check_circuit(&TestCircuit::new(program), K, &[], CheckMode::Strict)
        .is_ok_and(|report| report.is_satisfied())
}

fn report<F: PastaField>(program: Program<F>) -> String {
    check_circuit(&TestCircuit::new(program), K, &[], CheckMode::Strict).map_or_else(
        |error| format!("synthesis error: {error}"),
        |report| report.to_string(),
    )
}

/// The cells of `circuit` in the half-open row ranges `rows`, tampered one
/// at a time, that the strict checker misses (checked on up to eight
/// threads; the result is in cell order).
fn undetected_in_rows<F: PastaField>(
    circuit: &TestCircuit<F>,
    rows: &[(usize, usize)],
) -> Vec<(usize, usize)> {
    let cells: Vec<(usize, usize)> = assigned_advice_cells(circuit, K, &[])
        .expect("synthesis")
        .into_iter()
        .filter(|(_, row)| rows.iter().any(|(start, end)| (*start..*end).contains(row)))
        .collect();
    let workers = std::thread::available_parallelism().map_or(1, |n| n.get().min(8));
    let chunk = cells.len().div_ceil(workers).max(1);
    std::thread::scope(|scope| {
        // Spawn every worker before joining any, so the chunks run at once.
        let mut handles = Vec::with_capacity(workers);
        for part in cells.chunks(chunk) {
            handles.push(scope.spawn(move || {
                part.iter()
                    .filter(|(column, row)| {
                        let tamper = Tamper {
                            column: *column,
                            row: *row,
                            delta: F::ONE,
                        };
                        check_tampered(circuit, K, &[], Some(tamper))
                            .expect("checked")
                            .is_satisfied()
                    })
                    .copied()
                    .collect::<Vec<_>>()
            }));
        }
        let mut undetected = Vec::new();
        for handle in handles {
            undetected.extend(handle.join().expect("tamper worker"));
        }
        undetected
    })
}

#[test]
fn every_decomposition_unit_is_pinned_cell_by_cell() {
    for (index, value) in [
        (0, 0xdead_beef_u32),
        (1, 0x8000_0001),
        (2, 0x7fff_fffe),
        (3, 0x0123_4567),
    ] {
        let circuit = TestCircuit::<Fq>::new(Program::Decompose { spec: index, value });
        assert!(
            satisfied(circuit.program.clone()),
            "{}",
            report(circuit.program.clone())
        );
        assert_eq!(
            undetected_in_rows(&circuit, &[(0, 2)]),
            Vec::new(),
            "spec {index}"
        );
        // 13 columns hold at most 4 lookup cells, 14 bits and 4 outputs.
        let cells = assigned_advice_cells(&circuit, K, &[])
            .expect("synthesis")
            .len();
        assert!(cells <= 22, "spec {index}: {cells} cells");
    }
}

#[test]
fn split_accepts_only_the_xor_majority_halves() {
    let (a, b, c) = (0x1234_5678_u32, 0x9abc_def0_u32, 0x0f0f_f0f0_u32);
    let input = spread(a) + spread(b) + spread(c);
    let honest = (a ^ b ^ c, (a & b) ^ (a & c) ^ (b & c));
    assert!(satisfied::<Fq>(Program::Split {
        halves: honest,
        input
    }));
    // Swapped halves, a halves pair off by one in each, and a carry moved
    // between the halves all fail.
    assert!(!satisfied::<Fq>(Program::Split {
        halves: (honest.1, honest.0),
        input
    }));
    assert!(!satisfied::<Fq>(Program::Split {
        halves: (honest.0 ^ 1, honest.1),
        input
    }));
    assert!(!satisfied::<Fq>(Program::Split {
        halves: (honest.0 ^ 2, honest.1 ^ 1),
        input
    }));
    assert!(!satisfied::<Fp>(Program::Split {
        halves: honest,
        input: input + 1
    }));
    let circuit = TestCircuit::<Fp>::new(Program::Split {
        halves: honest,
        input,
    });
    assert_eq!(undetected_in_rows(&circuit, &[(0, 8)]), Vec::new());
}

#[test]
fn compress_matches_native_with_assigned_and_constant_words() {
    let block: [u32; 16] = core::array::from_fn(|index| {
        0x0101_0101_u32.wrapping_mul(u32::try_from(index).unwrap_or(0) + 3) ^ 0x5a5a_0000
    });
    let state = compress(&SHA256_IV, &block);
    for (assigned_state, constant_tail) in [(false, false), (true, false), (false, true)] {
        let program = Program::<Fq>::Compress {
            state: if assigned_state { state } else { SHA256_IV },
            assigned_state,
            block,
            constant_tail,
        };
        assert!(satisfied(program.clone()), "{}", report(program));
    }
}

#[test]
fn codec_rejects_non_canonical_and_out_of_range_digests() {
    // Honest digests in both placements (Fp digest in an Fq circuit, Fq
    // digest in its own field).
    let m = Fp::from(0x0102_0304_0506_0708_u64) * Fp::from_u128(u128::MAX);
    let as_fq = Fq::from_repr(m.to_repr()).into_option().expect("p < q");
    assert!(satisfied(Program::Digest {
        digest: as_fq,
        fp: true,
        forged: None
    }));
    assert!(satisfied(Program::Digest {
        digest: -Fq::ONE,
        fp: false,
        forged: None
    }));
    // The alias m + q of a small Fq value recomposes to the same cell but is
    // not below |Fp|.
    let small = Fq::from(5_u64);
    let alias = add_modulus::<Fq>(&canonical_u32_limbs(&small));
    assert!(!satisfied(Program::Digest {
        digest: small,
        fp: true,
        forged: Some(alias)
    }));
    // Honest bytes of the cell, but the cell is not a canonical Fp value
    // (p <= value < q).
    let between = Fq::from_repr(add_one(&(-Fp::ONE).to_repr()))
        .into_option()
        .expect("p < q");
    assert!(!satisfied(Program::Digest {
        digest: between,
        fp: true,
        forged: None
    }));
    // The largest canonical Fp value passes.
    let max = Fq::from_repr((-Fp::ONE).to_repr())
        .into_option()
        .expect("p < q");
    assert!(satisfied(Program::Digest {
        digest: max,
        fp: true,
        forged: None
    }));
    // Bytes of a different digest fail the recomposition.
    let other = digest_message(&Fp::from(6_u64));
    assert!(!satisfied(Program::Digest {
        digest: small,
        fp: true,
        forged: Some(other)
    }));
}

#[test]
fn codec_refuses_a_digest_field_wider_than_the_circuit_field() {
    let program = Program::<Fp>::Digest {
        digest: Fp::ONE,
        fp: false,
        forged: None,
    };
    assert_eq!(
        check_circuit(&TestCircuit::new(program), K, &[], CheckMode::Strict).err(),
        Some(Error::Synthesis)
    );
}

#[test]
fn digest_circuit_cells_are_pinned_in_every_unit_kind() {
    let m = Fp::from(0xfeed_u64).pow_vartime([7]);
    let digest = Fq::from_repr(m.to_repr()).into_option().expect("p < q");
    let circuit = TestCircuit::new(Program::Digest {
        digest,
        fp: true,
        forged: None,
    });
    assert!(satisfied(circuit.program.clone()));
    // Rows: codec 0..48 (byte units 0..32, borrow units 32..48), message
    // decompositions 48..62, schedule t = 16 at 62..72, rounds from 542
    // (round 1 at 566..590), feed-forward 2078..2094. One unit of every
    // kind and gate is covered.
    let rows = [
        (0, 4),
        (30, 36),
        (46, 50),
        (62, 72),
        (566, 590),
        (2076, 2080),
    ];
    assert_eq!(undetected_in_rows(&circuit, &rows), Vec::new());
}

/// `limbs + |F|` as 32 little-endian bytes (for small `limbs`).
fn add_modulus<F: PastaField>(limbs: &[u32; 8]) -> [u8; 32] {
    let modulus = canonical_u32_limbs(&-F::ONE);
    let mut out = [0_u8; 32];
    let mut carry = 1_u64; // |F| = (|F| - 1) + 1
    for (index, chunk) in out.chunks_exact_mut(4).enumerate() {
        let total = u64::from(limbs[index]) + u64::from(modulus[index]) + carry;
        let bytes = total.to_le_bytes();
        chunk.copy_from_slice(&bytes[..4]);
        carry = total >> 32;
    }
    out
}

/// `bytes + 1` as a little-endian integer.
fn add_one(bytes: &[u8; 32]) -> [u8; 32] {
    let mut out = *bytes;
    for byte in &mut out {
        let (sum, overflow) = byte.overflowing_add(1);
        *byte = sum;
        if !overflow {
            break;
        }
    }
    out
}

#[test]
fn test_helpers() {
    assert_eq!(
        add_one(&[
            0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0
        ])[..2],
        [0, 1]
    );
    let alias = add_modulus::<Fq>(&canonical_u32_limbs(&Fq::from(5_u64)));
    let reduced = Fq::from_raw_reduced(core::array::from_fn(|index| {
        u64::from_le_bytes(alias[8 * index..8 * index + 8].try_into().expect("8 bytes"))
    }));
    assert_eq!(reduced, Fq::from(5_u64));
    assert_eq!(low_u128(&Fq::from(9_u64)), 9);
    assert_eq!(digest_block(&Fp::ONE)[0], 0x0100_0000);
    for spec in [HALF, DECOMPOSE_A, DECOMPOSE_E, DECOMPOSE_W] {
        assert!(SPECS.contains(&spec));
    }
}

#[test]
fn range_check_accepts_exactly_32_bit_words() {
    for word in [0, 1, 0xffff_ffff] {
        assert!(satisfied::<Fq>(Program::RangeCheck { value: word }));
    }
    for word in [1 << 32, (1 << 32) + 5, u64::MAX] {
        assert!(!satisfied::<Fq>(Program::RangeCheck { value: word }));
    }
    let circuit = TestCircuit::<Fp>::new(Program::RangeCheck { value: 0x89ab_cdef });
    assert_eq!(undetected_in_rows(&circuit, &[(0, 2)]), Vec::new());
}

#[test]
fn configure_takes_the_columns_in_order() {
    let mut meta = ConstraintSystem::<Fq>::new();
    let advice: [Column<Advice>; SHA256_ADVICE_COLUMNS] =
        core::array::from_fn(|_| meta.advice_column());
    let constants = meta.fixed_column();
    let config = Sha256Config::configure(&mut meta, advice, constants);
    assert_eq!(config.advice_columns(), advice);
    assert_eq!(meta.lookups().len(), 1);
    assert_eq!(meta.constants(), [constants].as_slice());
    // The four word columns and the constants column are equality-enabled.
    assert_eq!(meta.permutation().columns().len(), 5);
    let chip = Sha256Chip::<Fq>::starting_at(&config, 7);
    assert_eq!(chip.next_row(), 7);
    assert_eq!(chip.config(), &config);
}
