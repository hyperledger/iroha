//! The Pow5 lane over Fq (`P_Fq`, `iroha_plonk_gadgets::pow5_fq`):
//!
//! - the pinned RP57 Fq permutation vectors, natively and in circuit, with
//!   the full output state exposed (M3 named test
//!   `pow5_fq_lane_matches_rp57_fq_vectors`);
//! - the KAGEMUSHA domain sponge over Fq against the shared
//!   `kagemusha_v1_poseidon.fq` vectors of `fixtures/native_prover/kats_v1.json`;
//! - the transcript (duplex) mode against the Pallas `poseidon_transcript`
//!   scripts of the same fixture and the native `Sponge`;
//! - per-cell tamper suites, misuse errors, the inventory (37 rows and 148
//!   cells per permutation, one cell per tap, degree 6), a real Pallas proof,
//!   and an ignored k = 16 release measurement.

use std::{convert::Infallible, path::PathBuf, time::Instant};

use ff::{Field as _, PrimeField as _};
use iroha_pasta::{
    Ep, Fq,
    msm::MemoryBudget,
    poseidon::{PoseidonField as _, Sponge, WIDTH, hash, permute},
};
use iroha_plonk::{
    ProverConfig, ProverRandomness,
    check::{CheckFailure, CheckMode, check_circuit},
    cs::{
        Advice, Column, ConstraintSystem, Instance, InstanceModeV1, ProofSuffixV1, Rotation,
        Selector, TranscriptV1,
    },
    frontend::{
        Cell, Circuit, Error, Layouter, Region, SimpleFloorPlanner, Value, configure, synthesize,
    },
    keys::{KeygenConfig, keygen_pk},
    pcs::ipa::PinnedParams,
    prove_circuit, verify_full,
};
use iroha_plonk_gadgets::{
    GlueChip, GlueConfig,
    cells::known,
    poseidon::{
        Absorb, AbsorbInput, Pow5Columns, Pow5State, RoundConstantColumns, domain_permutations,
    },
    pow5_fq::{
        CELLS_PER_PERMUTATION, DuplexFqChip, DuplexFqConfig, Pow5FqChip, Pow5FqConfig,
        ROWS_PER_PERMUTATION, RP57_FQ_PERMUTATION_VECTORS, RP57_FQ_ZERO_CHAIN8, duplex_native,
        hash_fq, permute_fq, squeeze_permutations,
        vectors::{decode_state, decode_word},
    },
    tamper::{Tamper, check_tampered, undetected_tampers},
};
use norito::json::Value as Json;
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

/// The chips a program drives.
struct Chips {
    /// Witnesses and constants.
    glue: GlueChip<Fq>,
    /// A bare lane whose start states are the shape's `starts`, with the
    /// test-only exposure of its states (absent in the measurement shape).
    bare: Option<(Pow5FqChip, StateOut)>,
    /// The transcript-mode lane (and its domain sponge).
    duplex: DuplexFqChip,
}

impl Chips {
    /// The bare lane and its state exposure.
    fn bare(&mut self) -> Result<(&mut Pow5FqChip, StateOut), Error> {
        let (lane, out) = self.bare.as_mut().ok_or(Error::Synthesis)?;
        Ok((lane, *out))
    }
}

/// Test-only: three equality-enabled columns and a gate copying the bare
/// lane's state words on a row into them, so a test can expose a full state
/// (the lane's state columns are not equality-enabled).
#[derive(Clone, Copy, Debug)]
struct StateOut {
    columns: [Column<Advice>; WIDTH],
    selector: Selector,
}

impl StateOut {
    fn configure(meta: &mut ConstraintSystem<Fq>, lane: Pow5Columns) -> Self {
        let columns: [Column<Advice>; WIDTH] = core::array::from_fn(|_| meta.advice_column());
        for column in columns {
            meta.enable_equality(column);
        }
        let selector = meta.selector();
        meta.create_gate("test state out", |cells| {
            let q = cells.query_selector(selector);
            (0..WIDTH)
                .map(|i| {
                    let out = cells.query_advice(columns[i], Rotation::cur());
                    let state = cells.query_advice(lane.state[i], Rotation::cur());
                    q.clone() * (out - state)
                })
                .collect::<Vec<_>>()
        });
        Self { columns, selector }
    }

    /// Exposes the state at row 0 of `state`'s block.
    fn expose(
        &self,
        region: &mut Region<'_, Fq>,
        state: &Pow5State<Fq>,
    ) -> Result<Vec<Cell>, Error> {
        let row = state
            .block()
            .checked_mul(ROWS_PER_PERMUTATION)
            .ok_or(Error::BoundsFailure)?;
        self.selector.enable(region, row)?;
        let value = state.value();
        let mut cells = Vec::with_capacity(WIDTH);
        for (index, column) in self.columns.into_iter().enumerate() {
            let assigned = region.assign_advice(column, row, value.map(|state| state[index]))?;
            cells.push(assigned.cell());
        }
        Ok(cells)
    }
}

/// The witness inputs and configuration-time arguments of a program.
struct Inputs {
    values: Vec<Fq>,
    known: bool,
    args: Vec<u64>,
}

impl Inputs {
    fn get(&self, index: usize) -> Value<Fq> {
        match self.values.get(index) {
            Some(value) if self.known => Value::known(*value),
            _ => Value::unknown(),
        }
    }

    fn all(&self) -> Vec<Value<Fq>> {
        (0..self.values.len())
            .map(|index| self.get(index))
            .collect()
    }

    fn arg(&self, index: usize) -> u64 {
        self.args.get(index).copied().unwrap_or(0)
    }
}

/// A program over the chips; its cells are exposed publicly in order.
type Program = fn(&mut Chips, &mut Region<'_, Fq>, &Inputs) -> Result<Vec<Cell>, Error>;

/// The configuration-time shape.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct LaneShape {
    /// Start states of the bare lane.
    starts: Vec<[Fq; WIDTH]>,
    /// Folded `(domain, arity)` prefixes of the duplex lane.
    folded: Vec<(u64, usize)>,
    /// Public outputs.
    public: usize,
    /// Program arguments.
    args: Vec<u64>,
    /// Only the glue chip and the duplex lane (the measurement shape).
    duplex_only: bool,
}

#[derive(Clone, Debug)]
struct LaneConfig {
    glue: GlueConfig,
    bare: Option<(Pow5FqConfig, StateOut)>,
    duplex: DuplexFqConfig,
    instance: Column<Instance>,
}

#[derive(Clone)]
struct LaneCircuit {
    shape: LaneShape,
    program: Program,
    inputs: Vec<Fq>,
    known: bool,
}

impl LaneCircuit {
    fn new(shape: LaneShape, program: Program, inputs: Vec<Fq>) -> Self {
        Self {
            shape,
            program,
            inputs,
            known: true,
        }
    }
}

impl Circuit<Fq> for LaneCircuit {
    type Config = LaneConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = LaneShape;

    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }

    fn params(&self) -> LaneShape {
        self.shape.clone()
    }

    fn configure(meta: &mut ConstraintSystem<Fq>) -> LaneConfig {
        Self::configure_with_params(meta, LaneShape::default())
    }

    fn configure_with_params(meta: &mut ConstraintSystem<Fq>, shape: LaneShape) -> LaneConfig {
        let advice: [Column<Advice>; 4] = core::array::from_fn(|_| meta.advice_column());
        let constants = meta.fixed_column();
        let glue = GlueConfig::configure(meta, advice, constants);
        let round_constants = RoundConstantColumns::allocate(meta);
        let bare = (!shape.duplex_only).then(|| {
            let lane = Pow5Columns::allocate(meta);
            let config = Pow5FqConfig::configure(meta, lane, round_constants, &shape.starts);
            (config, StateOut::configure(meta, lane))
        });
        let duplex_lane = Pow5Columns::allocate(meta);
        let duplex = DuplexFqConfig::configure(meta, duplex_lane, round_constants, &shape.folded);
        let instance = meta.instance_column(shape.public);
        meta.enable_equality(instance);
        LaneConfig {
            glue,
            bare,
            duplex,
            instance,
        }
    }

    fn synthesize(&self, config: LaneConfig, mut layouter: impl Layouter<Fq>) -> Result<(), Error> {
        let mut chips = Chips {
            glue: GlueChip::new(config.glue),
            bare: config.bare.map(|(bare, out)| (Pow5FqChip::new(bare), out)),
            duplex: DuplexFqChip::new(config.duplex),
        };
        let inputs = Inputs {
            values: self.inputs.clone(),
            known: self.known,
            args: self.shape.args.clone(),
        };
        let program = self.program;
        let outputs = layouter.assign_region(
            || "pow5 fq",
            |mut region| program(&mut chips, &mut region, &inputs),
        )?;
        if outputs.len() != self.shape.public {
            return Err(Error::Synthesis);
        }
        for (row, cell) in outputs.into_iter().enumerate() {
            layouter.constrain_instance(cell, config.instance, row)?;
        }
        Ok(())
    }
}

/// Advice column indices: glue `0..4`, the bare lane `4..8`, the state
/// exposure `8..11` and the duplex lane `11..15`; in the measurement shape
/// glue `0..4` and the duplex lane `4..8`.
const BARE: [usize; 4] = [4, 5, 6, 7];
const DUPLEX_ONLY: [usize; 4] = [4, 5, 6, 7];

fn accepts(circuit: &LaneCircuit, k: u32, public: &[Fq]) -> bool {
    check_circuit(circuit, k, &[public.to_vec()], CheckMode::Strict)
        .is_ok_and(|report| report.is_satisfied())
}

fn report(circuit: &LaneCircuit, k: u32, public: &[Fq]) -> String {
    check_circuit(circuit, k, &[public.to_vec()], CheckMode::Strict).map_or_else(
        |error| format!("synthesis error: {error}"),
        |report| report.to_string(),
    )
}

fn assigned(circuit: &LaneCircuit, k: u32, public: &[Fq]) -> Vec<Vec<bool>> {
    let synthesized = synthesize(circuit, k, Some(&[public.to_vec()][..])).expect("synthesis");
    synthesized.tables.advice_assigned().to_vec()
}

fn extent(flags: &[bool]) -> usize {
    flags
        .iter()
        .rposition(|flag| *flag)
        .map_or(0, |row| row + 1)
}

fn count(flags: &[bool]) -> usize {
    flags.iter().filter(|flag| **flag).count()
}

/// The smallest `k` whose usable rows (`2^k - 6`) hold `blocks` blocks.
fn k_for(blocks: usize) -> u32 {
    let rows = blocks * ROWS_PER_PERMUTATION;
    (6..=16)
        .find(|k| rows + 6 <= 1 << k)
        .unwrap_or_else(|| panic!("{blocks} blocks need k > 16"))
}

/// Fails synthesis when a known state differs from its expected value.
fn expect_state(value: Value<[Fq; WIDTH]>, expected: [Fq; WIDTH]) -> Result<(), Error> {
    match known(&value) {
        Some(value) if value != expected => Err(Error::Synthesis),
        _ => Ok(()),
    }
}

/// The first configured start state of the bare lane.
fn first_start(lane: &Pow5FqChip) -> Result<[Fq; WIDTH], Error> {
    lane.config()
        .initial_states()
        .next()
        .copied()
        .ok_or(Error::Synthesis)
}

// ---------------------------------------------------------------------------
// Permutation vectors.
// ---------------------------------------------------------------------------

/// One plain permutation of the configured start state, the full output
/// exposed; the output must equal input 0..3 natively.
fn plain_permutation(
    chips: &mut Chips,
    region: &mut Region<'_, Fq>,
    inputs: &Inputs,
) -> Result<Vec<Cell>, Error> {
    let (lane, out) = chips.bare()?;
    let start = first_start(lane)?;
    let state = lane.start(region, start)?;
    let next = lane.permute(region, state, Absorb::Nothing)?;
    if inputs.known {
        expect_state(next.value(), permute_fq(start, [Fq::ZERO; 2]))?;
    }
    out.expose(region, &next)
}

/// From the start state `[a, 0, 0]`, absorbs witnesses `b, c` and permutes:
/// the permutation of `[a, b, c]`, exposed in full.
fn absorbed_permutation(
    chips: &mut Chips,
    region: &mut Region<'_, Fq>,
    inputs: &Inputs,
) -> Result<Vec<Cell>, Error> {
    let words = chips.glue.witnesses(region, &inputs.all())?;
    let [b, c] = [&words[0], &words[1]];
    let (lane, out) = chips.bare()?;
    let start = first_start(lane)?;
    let state = lane.start(region, start)?;
    let next = lane.permute(
        region,
        state,
        Absorb::Block([AbsorbInput::Word(b), AbsorbInput::Word(c)]),
    )?;
    out.expose(region, &next)
}

/// The squeeze gate over Fq: word 1 of the permutation of the start state.
fn squeezed_permutation(
    chips: &mut Chips,
    region: &mut Region<'_, Fq>,
    _inputs: &Inputs,
) -> Result<Vec<Cell>, Error> {
    let (lane, _) = chips.bare()?;
    let start = first_start(lane)?;
    let state = lane.start(region, start)?;
    let word = lane.squeeze(region, state, Absorb::Nothing)?;
    Ok(vec![word.cell()])
}

/// `arg 0` chained plain permutations of the start state, exposed in full.
fn chained_permutations(
    chips: &mut Chips,
    region: &mut Region<'_, Fq>,
    inputs: &Inputs,
) -> Result<Vec<Cell>, Error> {
    let (lane, out) = chips.bare()?;
    let start = first_start(lane)?;
    let mut state = lane.start(region, start)?;
    for _ in 0..inputs.arg(0) {
        state = lane.permute(region, state, Absorb::Nothing)?;
    }
    out.expose(region, &state)
}

fn bare_shape(start: [Fq; WIDTH], public: usize) -> LaneShape {
    LaneShape {
        starts: vec![start],
        public,
        ..LaneShape::default()
    }
}

#[test]
fn pow5_fq_lane_matches_rp57_fq_vectors() {
    // The table the lane reads is the vendored RP57 Fq table.
    assert_eq!(
        fixture_constants(),
        (*Fq::rp57().round_constants(), *Fq::rp57().mds())
    );
    assert_ne!(Fq::rp57().to_table(), iroha_pasta::Fp::rp57().to_table());
    let k = k_for(2);
    for vector in RP57_FQ_PERMUTATION_VECTORS {
        let label = vector.label;
        let (input, output) = vector.decode().expect(label);
        // Native: the iroha_pasta permutation and the module reference.
        let mut native = input;
        permute(&mut native);
        assert_eq!(native, output, "native {label}");
        assert_eq!(
            permute_fq(input, [Fq::ZERO; 2]),
            output,
            "permute_fq {label}"
        );
        // In circuit, a plain permutation with the whole output exposed.
        let plain = LaneCircuit::new(bare_shape(input, WIDTH), plain_permutation, Vec::new());
        assert!(
            accepts(&plain, k, &output),
            "{label}: {}",
            report(&plain, k, &output)
        );
        for word in 0..WIDTH {
            let mut wrong = output;
            wrong[word] += Fq::ONE;
            assert!(
                !accepts(&plain, k, &wrong),
                "{label}: word {word} +1 accepted"
            );
        }
        // Words 1 and 2 entering through the absorb gate as witnesses.
        let absorbed = LaneCircuit::new(
            bare_shape([input[0], Fq::ZERO, Fq::ZERO], WIDTH),
            absorbed_permutation,
            vec![input[1], input[2]],
        );
        assert!(
            accepts(&absorbed, k, &output),
            "{label} absorbed: {}",
            report(&absorbed, k, &output)
        );
        // Another witness gives another state.
        let other = LaneCircuit::new(
            absorbed.shape.clone(),
            absorbed_permutation,
            vec![input[1] + Fq::ONE, input[2]],
        );
        assert!(
            !accepts(&other, k, &output),
            "{label}: wrong witness accepted"
        );
        // The squeeze gate: word 1.
        let squeezed = LaneCircuit::new(bare_shape(input, 1), squeezed_permutation, Vec::new());
        assert!(accepts(&squeezed, k, &output[1..2]), "{label} squeezed");
        assert!(!accepts(&squeezed, k, &[output[1] + Fq::ONE]));
    }
    // Eight chained permutations of the zero state.
    let chain8 = decode_state(&RP57_FQ_ZERO_CHAIN8).expect("chain vector");
    let shape = LaneShape {
        args: vec![8],
        ..bare_shape([Fq::ZERO; WIDTH], WIDTH)
    };
    let chained = LaneCircuit::new(shape, chained_permutations, Vec::new());
    let k = k_for(9);
    assert!(
        accepts(&chained, k, &chain8),
        "{}",
        report(&chained, k, &chain8)
    );
    let mut wrong = chain8;
    wrong[0] += Fq::ONE;
    assert!(!accepts(&chained, k, &wrong));
}

#[test]
fn pow5_fq_lane_every_assigned_cell_is_pinned() {
    let (input, output) = RP57_FQ_PERMUTATION_VECTORS[6].decode().expect("vector");
    let circuit = LaneCircuit::new(
        bare_shape([input[0], Fq::ZERO, Fq::ZERO], WIDTH),
        absorbed_permutation,
        vec![input[1], input[2]],
    );
    let undetected = undetected_tampers(&circuit, k_for(2), &[output.to_vec()]).expect("tampers");
    assert_eq!(undetected, Vec::<(usize, usize)>::new());
    let squeezed = LaneCircuit::new(bare_shape(input, 1), squeezed_permutation, Vec::new());
    let undetected = undetected_tampers(&squeezed, k_for(1), &[vec![output[1]]]).expect("tampers");
    assert_eq!(undetected, Vec::<(usize, usize)>::new());
}

#[test]
fn pow5_fq_lane_round_cases_are_rejected() {
    // One tamper per row kind of the M8 case list, on Fq.
    let (input, output) = RP57_FQ_PERMUTATION_VECTORS[7].decode().expect("vector");
    let circuit = LaneCircuit::new(
        bare_shape([input[0], Fq::ZERO, Fq::ZERO], WIDTH),
        absorbed_permutation,
        vec![input[1], input[2]],
    );
    let [s0, s1, s2, aux] = BARE;
    let cases = [
        ("start state word 0", s0, 0),
        ("absorbed word 1", aux, 0),
        ("absorbed word 2", aux, 1),
        ("full round", s1, 2),
        ("pair round", s2, 10),
        ("pair S-box", aux, 12),
        ("single partial round", s0, 32),
        ("last full round", s1, 36),
        ("state leaving the permutation", s2, ROWS_PER_PERMUTATION),
        ("exposed word", 8, ROWS_PER_PERMUTATION),
    ];
    for (label, column, row) in cases {
        let tamper = Tamper {
            column,
            row,
            delta: Fq::ONE,
        };
        let report =
            check_tampered(&circuit, k_for(2), &[output.to_vec()], Some(tamper)).expect("checked");
        assert!(!report.is_satisfied(), "{label} tamper accepted");
    }
    // A squeezed output and its public value moved together: only the
    // squeeze gate rejects it.
    let squeezed = LaneCircuit::new(bare_shape(input, 1), squeezed_permutation, Vec::new());
    let failures = forged_output_failures(
        &squeezed,
        k_for(1),
        &output[1..2],
        0,
        BARE[3],
        ROWS_PER_PERMUTATION - 1,
    );
    assert_eq!(failures, vec!["pow5 squeeze round".to_owned()]);
}

// ---------------------------------------------------------------------------
// The domain sponge over Fq.
// ---------------------------------------------------------------------------

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixture() -> Json {
    let path = repo_root().join("fixtures/native_prover/kats_v1.json");
    let text = std::fs::read_to_string(&path).expect("read kats_v1.json");
    norito::json::parse_value(&text).expect("parse kats_v1.json")
}

fn word(text: &str) -> Fq {
    decode_word(text).unwrap_or_else(|| panic!("canonical Fq word {text}"))
}

/// The `poseidon_constants.fq` table of the fixture.
fn fixture_constants() -> ([[Fq; WIDTH]; 65], [[Fq; WIDTH]; WIDTH]) {
    let fixture = fixture();
    let section = fixture
        .get("poseidon_constants")
        .and_then(|section| section.get("fq"))
        .expect("poseidon_constants.fq");
    let rows = |key: &str| -> Vec<[Fq; WIDTH]> {
        section
            .get(key)
            .and_then(Json::as_array)
            .expect("rows")
            .iter()
            .map(|row| {
                let row = row.as_array().expect("row");
                core::array::from_fn(|i| word(row[i].as_str().expect("hex")))
            })
            .collect()
    };
    let constants = rows("round_constants").try_into().expect("65 rows");
    let mds = rows("mds").try_into().expect("3 rows");
    (constants, mds)
}

/// `P_Fq(arg 0, inputs)` on the duplex lane's sponge.
fn domain_hash(
    chips: &mut Chips,
    region: &mut Region<'_, Fq>,
    inputs: &Inputs,
) -> Result<Vec<Cell>, Error> {
    let words = chips.glue.witnesses(region, &inputs.all())?;
    let digest = chips
        .duplex
        .sponge_mut()?
        .hash_words(region, inputs.arg(0), &words)?;
    Ok(vec![digest.cell()])
}

fn domain_circuit(domain: u64, inputs: Vec<Fq>, folded: bool) -> LaneCircuit {
    let shape = LaneShape {
        folded: if folded {
            vec![(domain, inputs.len())]
        } else {
            Vec::new()
        },
        public: 1,
        args: vec![domain],
        duplex_only: true,
        ..LaneShape::default()
    };
    LaneCircuit::new(shape, domain_hash, inputs)
}

#[test]
fn pow5_fq_domain_sponge_matches_the_shared_fq_vectors() {
    let fixture = fixture();
    let vectors = fixture
        .get("kagemusha_v1_poseidon")
        .and_then(|section| section.get("fq"))
        .and_then(|section| section.get("vectors"))
        .and_then(Json::as_array)
        .expect("kagemusha_v1_poseidon.fq vectors");
    assert_eq!(vectors.len(), 12);
    for vector in vectors {
        let text = |key: &str| vector.get(key).and_then(Json::as_str).expect("string");
        let label = text("domain");
        let domain = u64::from_le_bytes(label.as_bytes().try_into().expect("8-byte domain"));
        let inputs = vector
            .get("inputs")
            .and_then(Json::as_array)
            .expect("inputs")
            .iter()
            .map(|input| word(input.as_str().expect("hex")))
            .collect::<Vec<_>>();
        let output = word(text("output"));
        assert_eq!(hash_fq(domain, &inputs), output, "native {label}");
        for folded in [false, true] {
            let blocks = domain_permutations(inputs.len(), folded);
            let k = k_for(blocks);
            let circuit = domain_circuit(domain, inputs.clone(), folded);
            assert!(
                accepts(&circuit, k, &[output]),
                "{label} arity {} folded {folded}: {}",
                inputs.len(),
                report(&circuit, k, &[output])
            );
            assert!(!accepts(&circuit, k, &[output + Fq::ONE]));
            let flags = assigned(&circuit, k, &[output]);
            assert_eq!(
                extent(&flags[DUPLEX_ONLY[0]]),
                blocks * ROWS_PER_PERMUTATION,
                "{label} lane rows"
            );
        }
    }
}

#[test]
fn pow5_fq_domain_sponge_cells_are_pinned() {
    let domain = u64::from_le_bytes(*b"kgmleaf1");
    let inputs = vec![Fq::from(7u64), -Fq::ONE, Fq::from(9u64)];
    let output = hash_fq(domain, &inputs);
    for folded in [false, true] {
        let circuit = domain_circuit(domain, inputs.clone(), folded);
        let k = k_for(domain_permutations(inputs.len(), folded));
        let undetected = undetected_tampers(&circuit, k, &[vec![output]]).expect("tampers");
        assert_eq!(undetected, Vec::<(usize, usize)>::new(), "folded {folded}");
        // The digest cell and the public digest moved together.
        let blocks = domain_permutations(inputs.len(), folded);
        let row = blocks * ROWS_PER_PERMUTATION - 1;
        let failures = forged_output_failures(&circuit, k, &[output], 0, DUPLEX_ONLY[3], row);
        assert_eq!(
            failures,
            vec!["pow5 squeeze round".to_owned()],
            "folded {folded}"
        );
    }
}

// ---------------------------------------------------------------------------
// The transcript (duplex) mode.
// ---------------------------------------------------------------------------

/// One transcript operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    /// Absorb the next witness input.
    Witness,
    /// Absorb a constant.
    Constant(u64),
    /// Squeeze with the state carried on (a tap).
    Squeeze,
    /// Squeeze and clear (the squeeze gate).
    Last,
    /// Clear without squeezing.
    Clear,
    /// A domain hash `P_Fq(7, [next witness])` on the lane between
    /// transcripts.
    Hash,
}

/// Encodes a script as program arguments.
fn encode(ops: &[Op]) -> Vec<u64> {
    ops.iter()
        .map(|op| match op {
            Op::Witness => 1 << 60,
            Op::Squeeze => 2 << 60,
            Op::Last => 3 << 60,
            Op::Clear => 4 << 60,
            Op::Hash => 5 << 60,
            Op::Constant(value) => *value,
        })
        .collect()
}

fn decode(arg: u64) -> Op {
    match arg >> 60 {
        1 => Op::Witness,
        2 => Op::Squeeze,
        3 => Op::Last,
        4 => Op::Clear,
        5 => Op::Hash,
        _ => Op::Constant(arg),
    }
}

/// Runs the script in `args` on the duplex lane; outputs every squeeze and
/// hash.
fn transcript(
    chips: &mut Chips,
    region: &mut Region<'_, Fq>,
    inputs: &Inputs,
) -> Result<Vec<Cell>, Error> {
    let words = chips.glue.witnesses(region, &inputs.all())?;
    let mut next = words.iter();
    let mut outputs = Vec::new();
    for op in inputs.args.iter().copied().map(decode) {
        match op {
            Op::Witness => chips.duplex.absorb(next.next().ok_or(Error::Synthesis)?),
            Op::Constant(value) => chips.duplex.absorb_constant(Fq::from(value)),
            Op::Squeeze => outputs.push(chips.duplex.squeeze(region)?.cell()),
            Op::Last => outputs.push(chips.duplex.squeeze_and_clear(region)?.cell()),
            Op::Clear => chips.duplex.clear(),
            Op::Hash => {
                let word = next.next().ok_or(Error::Synthesis)?;
                let digest = chips.duplex.sponge_mut()?.hash_words(
                    region,
                    7,
                    core::slice::from_ref(word),
                )?;
                outputs.push(digest.cell());
            }
        }
    }
    Ok(outputs)
}

/// The native outputs of a script.
fn transcript_native(ops: &[Op], witnesses: &[Fq]) -> Vec<Fq> {
    let mut sponge = Sponge::<Fq>::new();
    let mut next = witnesses.iter();
    let mut outputs = Vec::new();
    for op in ops {
        match op {
            Op::Witness => sponge.update(&[*next.next().expect("witness")]),
            Op::Constant(value) => sponge.update(&[Fq::from(*value)]),
            Op::Squeeze => outputs.push(sponge.squeeze()),
            Op::Last => {
                outputs.push(sponge.squeeze());
                sponge.clear();
            }
            Op::Clear => sponge.clear(),
            Op::Hash => outputs.push(hash_fq(7, &[*next.next().expect("witness")])),
        }
    }
    outputs
}

/// The blocks a script lays out.
fn transcript_blocks(ops: &[Op]) -> usize {
    let mut blocks = 0;
    let mut buffered = 0;
    let mut live = false;
    for op in ops {
        match op {
            Op::Witness | Op::Constant(_) => buffered += 1,
            Op::Squeeze => {
                blocks += squeeze_permutations(buffered) + usize::from(!live);
                buffered = 0;
                live = true;
            }
            Op::Last => {
                blocks += squeeze_permutations(buffered) - usize::from(live);
                buffered = 0;
                live = false;
            }
            Op::Clear => {
                buffered = 0;
                live = false;
            }
            Op::Hash => blocks += domain_permutations(1, false),
        }
    }
    blocks
}

fn transcript_circuit(ops: &[Op], witnesses: Vec<Fq>) -> (LaneCircuit, Vec<Fq>) {
    let public = transcript_native(ops, &witnesses);
    let shape = LaneShape {
        public: public.len(),
        args: encode(ops),
        duplex_only: true,
        ..LaneShape::default()
    };
    (LaneCircuit::new(shape, transcript, witnesses), public)
}

/// A fixture transcript script: its name, operations, absorbed scalars and
/// challenges.
struct Script {
    name: String,
    ops: Vec<Op>,
    witnesses: Vec<Fq>,
    challenges: Vec<Fq>,
}

/// The `poseidon_transcript.ep` scripts that only absorb scalars: the
/// Pallas transcript runs the sponge over its scalar field Fq.
fn pallas_scalar_scripts() -> Vec<Script> {
    let fixture = fixture();
    let scripts = fixture
        .get("poseidon_transcript")
        .and_then(|section| section.get("ep"))
        .and_then(|section| section.get("scripts"))
        .and_then(Json::as_array)
        .expect("poseidon_transcript.ep scripts");
    let mut out = Vec::new();
    for script in scripts {
        let name = script
            .get("name")
            .and_then(Json::as_str)
            .expect("name")
            .to_owned();
        if name != "squeeze_only" && name != "scalars" {
            continue;
        }
        let mut ops = Vec::new();
        let mut witnesses = Vec::new();
        let mut challenges = Vec::new();
        for op in script.get("ops").and_then(Json::as_array).expect("ops") {
            let text = |key: &str| op.get(key).and_then(Json::as_str).expect("string");
            match text("op") {
                "common_scalar" => {
                    ops.push(Op::Witness);
                    witnesses.push(word(text("value")));
                }
                "squeeze" => {
                    ops.push(Op::Squeeze);
                    challenges.push(word(text("challenge")));
                }
                other => panic!("unexpected op {other}"),
            }
        }
        out.push(Script {
            name,
            ops,
            witnesses,
            challenges,
        });
    }
    assert_eq!(out.len(), 2);
    out
}

#[test]
fn pow5_fq_duplex_matches_the_pallas_transcript_scripts() {
    for Script {
        name,
        mut ops,
        witnesses,
        challenges,
    } in pallas_scalar_scripts()
    {
        let script = {
            let mut chunks = Vec::new();
            let mut pending = Vec::new();
            let mut next = witnesses.iter();
            for op in &ops {
                match op {
                    Op::Witness => pending.push(*next.next().expect("witness")),
                    _ => chunks.push(core::mem::take(&mut pending)),
                }
            }
            chunks
        };
        assert_eq!(duplex_native(&script), challenges, "native {name}");
        assert_eq!(transcript_native(&ops, &witnesses), challenges);
        // Every squeeze continues; then the last one squeezes and clears.
        for last in [false, true] {
            if last {
                *ops.last_mut().expect("ops") = Op::Last;
            }
            let (circuit, public) = transcript_circuit(&ops, witnesses.clone());
            assert_eq!(public, challenges);
            let k = k_for(transcript_blocks(&ops) + 1);
            assert!(
                accepts(&circuit, k, &public),
                "{name} last {last}: {}",
                report(&circuit, k, &public)
            );
            for index in 0..public.len() {
                let mut wrong = public.clone();
                wrong[index] += Fq::ONE;
                assert!(!accepts(&circuit, k, &wrong), "{name}: challenge {index}");
            }
            // A continuing last squeeze leaves its state on row 0 of one
            // more block.
            let blocks = transcript_blocks(&ops);
            let rows = if last {
                blocks * ROWS_PER_PERMUTATION
            } else {
                (blocks - 1) * ROWS_PER_PERMUTATION + 1
            };
            let flags = assigned(&circuit, k, &public);
            assert_eq!(extent(&flags[DUPLEX_ONLY[0]]), rows, "{name} lane rows");
        }
    }
}

/// A transcript exercising every operation: odd and even buffers,
/// constants, an empty squeeze, a final squeeze, a hash between
/// transcripts and a cleared live state.
fn mixed_ops() -> Vec<Op> {
    vec![
        Op::Witness,
        Op::Squeeze,
        Op::Witness,
        Op::Constant(9),
        Op::Witness,
        Op::Squeeze,
        Op::Squeeze,
        Op::Constant(4),
        Op::Last,
        Op::Hash,
        Op::Witness,
        Op::Squeeze,
        Op::Clear,
        Op::Witness,
        Op::Witness,
        Op::Last,
    ]
}

fn mixed_witnesses() -> Vec<Fq> {
    vec![
        Fq::from(3u64),
        -Fq::ONE,
        Fq::from_u128(u128::MAX),
        Fq::ZERO,
        Fq::from(0x1234_5678u64),
        Fq::from(77u64),
        Fq::from(78u64),
    ]
}

#[test]
fn pow5_fq_duplex_matches_the_native_sponge() {
    let ops = mixed_ops();
    let (circuit, public) = transcript_circuit(&ops, mixed_witnesses());
    // Hand-check the first outputs against the plain sponge.
    let w = mixed_witnesses();
    let mut sponge = Sponge::<Fq>::new();
    sponge.update(&w[..1]);
    assert_eq!(public[0], sponge.squeeze());
    assert_eq!(public[4], hash(&[Fq::from(7u64), Fq::ONE, w[3]]));
    let k = k_for(transcript_blocks(&ops) + 1);
    assert!(
        accepts(&circuit, k, &public),
        "{}",
        report(&circuit, k, &public)
    );
    for index in 0..public.len() {
        let mut wrong = public.clone();
        wrong[index] += Fq::ONE;
        assert!(!accepts(&circuit, k, &wrong), "output {index}");
    }
    // A different witness changes every later challenge of its transcript.
    let mut other = mixed_witnesses();
    other[1] += Fq::ONE;
    let (forged, _) = transcript_circuit(&ops, other);
    assert!(!accepts(&forged, k, &public));
}

#[test]
fn pow5_fq_duplex_every_assigned_cell_is_pinned() {
    let ops = mixed_ops();
    let (circuit, public) = transcript_circuit(&ops, mixed_witnesses());
    let k = k_for(transcript_blocks(&ops) + 1);
    let undetected = undetected_tampers(&circuit, k, &[public]).expect("tampers");
    assert_eq!(undetected, Vec::<(usize, usize)>::new());
}

#[test]
fn pow5_fq_duplex_tap_is_bound_to_the_continuing_state() {
    // [x] squeeze (tap at row 36), [] squeeze (tap at row 73).
    let ops = [Op::Witness, Op::Squeeze, Op::Squeeze];
    let (circuit, public) = transcript_circuit(&ops, vec![Fq::from(5u64)]);
    let k = k_for(4);
    assert!(
        accepts(&circuit, k, &public),
        "{}",
        report(&circuit, k, &public)
    );
    let [_, s1, _, aux] = DUPLEX_ONLY;
    let last = ROWS_PER_PERMUTATION - 1;
    for (label, column, row) in [
        ("first tap", aux, last),
        ("state word 1 the first tap reads", s1, ROWS_PER_PERMUTATION),
        ("second tap", aux, ROWS_PER_PERMUTATION + last),
        ("dangling state word 1", s1, 2 * ROWS_PER_PERMUTATION),
    ] {
        let tamper = Tamper {
            column,
            row,
            delta: Fq::ONE,
        };
        let report = check_tampered(&circuit, k, core::slice::from_ref(&public), Some(tamper))
            .expect("checked");
        assert!(!report.is_satisfied(), "{label} tamper accepted");
    }
    // Consistent forgeries: a tap and its public challenge both moved. The
    // copy to the instance holds, so only the tap gate can reject it.
    for (index, row) in [(0, last), (1, ROWS_PER_PERMUTATION + last)] {
        let failures = forged_output_failures(&circuit, k, &public, index, aux, row);
        assert_eq!(failures, vec!["duplex tap".to_owned()], "tap {index}");
    }
    // The tap costs one cell and no row: aux holds 28 pair S-boxes, the two
    // absorbed words and one tap per block.
    let flags = assigned(&circuit, k, &public);
    assert_eq!(count(&flags[aux]), 2 * (28 + 2 + 1));
    assert_eq!(extent(&flags[aux]), 2 * ROWS_PER_PERMUTATION);
}

/// The names of the gates that fail when public output `index` and the
/// advice cell `(column, row)` that produced it are both moved by one: a
/// forgery every copy constraint accepts.
fn forged_output_failures(
    circuit: &LaneCircuit,
    k: u32,
    public: &[Fq],
    index: usize,
    column: usize,
    row: usize,
) -> Vec<String> {
    let mut forged = public.to_vec();
    forged[index] += Fq::ONE;
    let tamper = Tamper {
        column,
        row,
        delta: Fq::ONE,
    };
    let report = check_tampered(circuit, k, &[forged], Some(tamper)).expect("checked");
    let mut names = report
        .failures()
        .iter()
        .map(|failure| match failure {
            CheckFailure::ConstraintNotSatisfied { gate_name, .. } => gate_name.clone(),
            other => format!("{other:?}"),
        })
        .collect::<Vec<_>>();
    names.dedup();
    names
}

/// A hash on the lane while a transcript state is live.
fn hash_while_live(
    chips: &mut Chips,
    region: &mut Region<'_, Fq>,
    inputs: &Inputs,
) -> Result<Vec<Cell>, Error> {
    let words = chips.glue.witnesses(region, &inputs.all())?;
    chips.duplex.absorb(&words[0]);
    let challenge = chips.duplex.squeeze(region)?;
    let digest = chips.duplex.sponge_mut()?.hash_words(region, 7, &words)?;
    Ok(vec![challenge.cell(), digest.cell()])
}

/// A hash while words are buffered.
fn hash_while_buffered(
    chips: &mut Chips,
    region: &mut Region<'_, Fq>,
    inputs: &Inputs,
) -> Result<Vec<Cell>, Error> {
    let words = chips.glue.witnesses(region, &inputs.all())?;
    chips.duplex.absorb(&words[0]);
    let digest = chips.duplex.sponge_mut()?.hash_words(region, 7, &words)?;
    let challenge = chips.duplex.squeeze(region)?;
    Ok(vec![digest.cell(), challenge.cell()])
}

/// The bare lane started from a state that has no start gate.
fn unconfigured_start(
    chips: &mut Chips,
    region: &mut Region<'_, Fq>,
    _inputs: &Inputs,
) -> Result<Vec<Cell>, Error> {
    let (lane, _) = chips.bare()?;
    let state = lane.start(region, [Fq::ONE; WIDTH])?;
    Ok(vec![lane.squeeze(region, state, Absorb::Nothing)?.cell()])
}

#[test]
fn pow5_fq_lane_misuse_is_a_typed_error() {
    let x = Fq::from(5u64);
    let programs: [Program; 2] = [hash_while_live, hash_while_buffered];
    for program in programs {
        let shape = LaneShape {
            public: 2,
            duplex_only: true,
            ..LaneShape::default()
        };
        let circuit = LaneCircuit::new(shape, program, vec![x]);
        assert_eq!(
            synthesize(&circuit, 8, Some(&[vec![Fq::ZERO; 2]][..])).map(|_| ()),
            Err(Error::Synthesis)
        );
    }
    let circuit = LaneCircuit::new(
        bare_shape([Fq::ZERO; WIDTH], 1),
        unconfigured_start,
        Vec::new(),
    );
    assert_eq!(
        synthesize(&circuit, 7, Some(&[vec![Fq::ZERO]][..])).map(|_| ()),
        Err(Error::Synthesis)
    );
}

#[test]
fn pow5_fq_lane_inventory() {
    assert_eq!(ROWS_PER_PERMUTATION, 37);
    assert_eq!(CELLS_PER_PERMUTATION, 148);
    // A bare lane: 37 rows per block, 3 state words per row, 28 pair
    // S-boxes per block.
    let shape = LaneShape {
        args: vec![3],
        ..bare_shape([Fq::ZERO; WIDTH], WIDTH)
    };
    let chained = LaneCircuit::new(shape, chained_permutations, Vec::new());
    let mut state = [Fq::ZERO; WIDTH];
    for _ in 0..3 {
        permute(&mut state);
    }
    let k = k_for(4);
    let flags = assigned(&chained, k, &state);
    let [s0, s1, s2, aux] = BARE;
    for column in [s0, s1, s2] {
        // Three blocks and the state the last one leaves.
        assert_eq!(count(&flags[column]), 3 * ROWS_PER_PERMUTATION + 1);
    }
    assert_eq!(count(&flags[aux]), 3 * 28);
    assert_eq!(extent(&flags[aux]), 3 * ROWS_PER_PERMUTATION - 5);
    // The configuration: degree 6, every lane gate at most 6, the tap 2.
    let (cs, _) = configure(&chained).expect("configure");
    assert_eq!(cs.degree(), 6);
    assert_eq!(cs.blinding_factors(), 5);
    let degrees = cs
        .gates()
        .iter()
        .map(|gate| {
            let degree = gate
                .polynomials()
                .iter()
                .map(iroha_plonk::Expression::degree)
                .max()
                .unwrap_or(0);
            (gate.name().to_owned(), degree)
        })
        .collect::<Vec<_>>();
    assert!(
        degrees.iter().all(|(_, degree)| *degree <= 6),
        "{degrees:?}"
    );
    let tap = degrees
        .iter()
        .filter(|(name, _)| name == "duplex tap")
        .map(|(_, degree)| *degree)
        .collect::<Vec<_>>();
    assert_eq!(tap, vec![2]);
    // Columns of the measurement shape: glue 4 + lane 4 advice; constants,
    // 6 glue coefficients and 6 round constants fixed.
    let measurement = transcript_circuit(&[Op::Squeeze], Vec::new()).0;
    let (cs, _) = configure(&measurement).expect("configure");
    assert_eq!(cs.num_advice_columns(), 8);
    assert_eq!(cs.num_fixed_columns(), 13);
}

// ---------------------------------------------------------------------------
// Real proofs and the k = 16 measurement.
// ---------------------------------------------------------------------------

/// Proof bytes, keygen, prove and verify times of a Pallas proof of
/// `circuit` (the KAGEMUSHA transcript, Direct instances, folded-generator
/// suffix).
fn pallas_round_trip(circuit: &LaneCircuit, public: &[Fq], k: u32) -> (usize, [u128; 3]) {
    let started = Instant::now();
    let params = PinnedParams::<Ep>::derive(k).expect("params");
    let mut config = KeygenConfig::new(TranscriptV1::KagemushaPoseidonRp57);
    config.instance_mode = InstanceModeV1::Direct;
    config.proof_suffix = ProofSuffixV1::FoldedGenerator;
    let pk = keygen_pk(&params, &circuit.without_witnesses(), &config).expect("proving key");
    let keygen = started.elapsed().as_millis();
    let prove = |seed: u8| {
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
        .expect("proof")
    };
    let started = Instant::now();
    let proof = prove(7);
    let proving = started.elapsed().as_millis();
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
    assert_eq!(verify(public, &proof), Ok(()));
    let verifying = started.elapsed().as_millis();
    let mut wrong = public.to_vec();
    wrong[0] += Fq::ONE;
    assert!(verify(&wrong, &proof).is_err(), "wrong public input");
    let mut corrupted = proof.clone();
    let middle = corrupted.len() / 2;
    corrupted[middle] ^= 1;
    assert!(verify(public, &corrupted).is_err(), "corrupted proof");
    println!(
        "POW5_FQ_PROOF k={k} fixed_commitments={} bytes={} keygen_ms={keygen} prove_ms={proving} \
         verify_ms={verifying}",
        pk.vk().fixed_commitments().len(),
        proof.len()
    );
    (proof.len(), [keygen, proving, verifying])
}

#[test]
fn pow5_fq_lane_pallas_proof() {
    let ops = mixed_ops();
    let (circuit, public) = transcript_circuit(&ops, mixed_witnesses());
    let k = k_for(transcript_blocks(&ops) + 1).max(8);
    assert!(accepts(&circuit, k, &public));
    let (bytes, _) = pallas_round_trip(&circuit, &public, k);
    assert!(bytes > 0);
}

/// The measurement program: the σ-key and A-key digest shapes of the
/// design (`P_Fq` over 63 and 109 elements, folded), a verifier-shaped
/// transcript (40 rounds of two points then a squeeze), then empty squeezes
/// until the lane is full. Outputs: both digests and the last challenge.
fn measurement(
    chips: &mut Chips,
    region: &mut Region<'_, Fq>,
    inputs: &Inputs,
) -> Result<Vec<Cell>, Error> {
    let domain = inputs.arg(0);
    let capacity = usize::try_from(inputs.arg(1)).map_err(|_| Error::Synthesis)?;
    let words = chips.glue.witnesses(region, &inputs.all())?;
    let (sigma_key, rest) = words.split_at(63);
    let (a_key, transcript_words) = rest.split_at(109);
    let sponge = chips.duplex.sponge_mut()?;
    let sigma = sponge.hash_words(region, domain, sigma_key)?;
    let a = sponge.hash_words(region, domain, a_key)?;
    if transcript_words.is_empty() {
        return Err(Error::Synthesis);
    }
    for round in transcript_words.chunks(4) {
        chips.duplex.absorb_words(round);
        chips.duplex.squeeze(region)?;
    }
    while chips.duplex.lane().next_block() < capacity {
        chips.duplex.squeeze(region)?;
    }
    let challenge = chips.duplex.squeeze_and_clear(region)?;
    Ok(vec![sigma.cell(), a.cell(), challenge.cell()])
}

/// `RAYON_NUM_THREADS=1 cargo test -p iroha_plonk_gadgets --release --test
/// pow5_fq_lane -- --ignored --nocapture`
#[test]
#[ignore = "k = 16 Pallas proof of a full Fq lane; run in release"]
fn pow5_fq_lane_measurement_k16() {
    let k = 16;
    // A test-only domain word (no protocol domain).
    let domain = u64::from_le_bytes(*b"pfqtest1");
    let values = (0..63 + 109 + 160)
        .map(|i| Fq::from(0x9e37_79b9_u64 * (i + 1)))
        .collect::<Vec<_>>();
    // Usable rows at k = 16 with five blinding rows: 65,530, so 1,771
    // blocks; the transcript ends with a squeeze-and-clear, so every block
    // is a full permutation.
    let usable = (1usize << k) - 6;
    let capacity = usable / ROWS_PER_PERMUTATION;
    let sigma = hash_fq(domain, &values[..63]);
    let a = hash_fq(domain, &values[63..172]);
    // The transcript: the digests' blocks, then the reserved block of the
    // first continuing squeeze, then the blocks of every squeeze.
    let mut sponge = Sponge::<Fq>::new();
    let mut blocks = domain_permutations(63, true) + domain_permutations(109, true) + 1;
    for round in values[172..].chunks(4) {
        sponge.update(round);
        sponge.squeeze();
        blocks += squeeze_permutations(round.len());
    }
    while blocks < capacity {
        sponge.squeeze();
        blocks += 1;
    }
    let public = vec![sigma, a, sponge.squeeze()];
    let shape = LaneShape {
        folded: vec![(domain, 63), (domain, 109)],
        public: 3,
        args: vec![domain, capacity as u64],
        duplex_only: true,
        ..LaneShape::default()
    };
    let circuit = LaneCircuit::new(shape, measurement, values);
    let started = Instant::now();
    let synthesized = synthesize(&circuit, k, Some(&[public.clone()][..])).expect("synthesis");
    let synthesis = started.elapsed().as_millis();
    let flags = synthesized.tables.advice_assigned().to_vec();
    let started = Instant::now();
    assert!(
        accepts(&circuit, k, &public),
        "{}",
        report(&circuit, k, &public)
    );
    let check = started.elapsed().as_millis();
    let (cs, _) = configure(&circuit).expect("configure");
    let lane_rows = extent(&flags[DUPLEX_ONLY[0]]);
    let lane_cells: usize = DUPLEX_ONLY
        .iter()
        .map(|column| count(&flags[*column]))
        .sum();
    let glue_cells: usize = (0..4).map(|column| count(&flags[column])).sum();
    let glue_rows = extent(&flags[0]);
    let lane_blocks = lane_rows.div_ceil(ROWS_PER_PERMUTATION);
    println!(
        "POW5_FQ_SHAPE k={k} usable_rows={} advice={} fixed={} selectors={} instance={} \
         degree={} blinding={}",
        cs.usable_rows(k).expect("usable rows"),
        cs.num_advice_columns(),
        cs.num_fixed_columns(),
        cs.num_selectors(),
        cs.num_instance_columns(),
        cs.degree(),
        cs.blinding_factors()
    );
    println!(
        "POW5_FQ_CELLS lane_blocks={lane_blocks} lane_rows={lane_rows} lane_area_cells={} \
         lane_assigned_cells={lane_cells} glue_rows={glue_rows} glue_cells={glue_cells} \
         sigma_key_permutations={} a_key_permutations={} synthesis_ms={synthesis} check_ms={check}",
        lane_rows * 4,
        domain_permutations(63, true),
        domain_permutations(109, true)
    );
    assert_eq!(lane_rows, capacity * ROWS_PER_PERMUTATION);
    assert_eq!(lane_blocks, capacity);
    assert!(lane_rows <= usable);
    assert_eq!(domain_permutations(63, true), 32);
    assert_eq!(domain_permutations(109, true), 55);
    let (bytes, times) = pallas_round_trip(&circuit, &public, k);
    println!(
        "POW5_FQ_MEASURED k={k} permutations={capacity} proof_bytes={bytes} keygen_ms={} \
         prove_ms={} verify_ms={} rayon_threads={}",
        times[0],
        times[1],
        times[2],
        std::env::var("RAYON_NUM_THREADS").unwrap_or_else(|_| "default".to_owned())
    );
}
