//! Native ports of historical golden circuits captured before prover retirement
//! (originally `vendor/halo2-axiom/tests/golden_proof_bytes.rs`): the sigma-shaped
//! and wide circuit, written against the `iroha_plonk` frontend.
//!
//! They check that the frontend expresses the golden shapes (degree and
//! permutation width), that the constraint checker accepts the honest
//! witnesses and rejects tampered ones, and that their descriptors are
//! deterministic. The native unit suite `src/captured_goldens.rs` freshly
//! rebuilds circuits and compares keys and proof bytes with the retained corpus;
//! the deleted `iroha_plonk_oracle` is no longer a live comparison dependency.

use ff::{Field, PrimeField};
use iroha_pasta::{Fp, Fq, PastaField};
use iroha_plonk::{
    check::{CheckFailure, CheckMode, check},
    cs::{
        Advice, CircuitDescriptorV1, Column, ConstraintSystem, CurveV1, DescriptorConfig,
        Expression, Fixed, Instance, InstanceModeV1, ProofSuffixV1, Rotation, TableColumn,
        TranscriptV1,
    },
    frontend::{Cell, Circuit, Error, Layouter, SimpleFloorPlanner, Value, synthesize},
};
use rand_chacha::ChaCha20Rng;
use rand_core_06::{RngCore, SeedableRng};

/// Rows left unassigned at the end of the domain.
const RESERVED_ROWS: usize = 16;
/// Width of one Pow5-style lane.
const LANE_WIDTH: usize = 3;
/// Lanes of the sigma circuit.
const LANES: usize = 2;
/// Rows between two bus copies of the same lane.
const BUS_STRIDE: usize = 16;
/// Advice columns of the wide circuit.
const WIDE_ADVICE: usize = 12;
/// Product groups of the wide circuit.
const WIDE_GROUPS: usize = WIDE_ADVICE / 3;

fn used_rows(k: u32) -> usize {
    (1_usize << k) - RESERVED_ROWS
}

fn table_bits(k: u32) -> u32 {
    (k - 1).min(8)
}

fn data_rng(label: u8, k: u32) -> ChaCha20Rng {
    let mut seed = [0_u8; 32];
    seed[0] = label;
    seed[1] = u8::try_from(k).expect("k fits a byte");
    seed[31] = 0x5a;
    ChaCha20Rng::from_seed(seed)
}

fn small_nonzero(rng: &mut ChaCha20Rng, bits: u32) -> u64 {
    (rng.next_u64() & ((1_u64 << bits) - 1)).max(1)
}

fn lane_mds<F: Field>() -> [[F; LANE_WIDTH]; LANE_WIDTH] {
    let mut rng = data_rng(0xd5, 0);
    std::array::from_fn(|_| std::array::from_fn(|_| F::random(&mut rng)))
}

fn lane_round<F: Field>(
    mds: &[[F; LANE_WIDTH]; LANE_WIDTH],
    state: &[F; LANE_WIDTH],
    constants: &[F; LANE_WIDTH],
) -> [F; LANE_WIDTH] {
    let powers: [F; LANE_WIDTH] = std::array::from_fn(|i| {
        let shifted = state[i] + constants[i];
        shifted.square().square() * shifted
    });
    std::array::from_fn(|i| (0..LANE_WIDTH).fold(F::ZERO, |sum, j| sum + mds[i][j] * powers[j]))
}

#[derive(Clone)]
struct SigmaCircuit<F: PastaField> {
    k: u32,
    witness: bool,
    round_constants: Vec<[F; LANE_WIDTH]>,
    states: Vec<[[F; LANE_WIDTH]; LANES]>,
    bytes: Vec<F>,
}

#[derive(Clone, Copy)]
struct SigmaConfig {
    lanes: [[Column<Advice>; LANE_WIDTH]; LANES],
    bus: Column<Advice>,
    base: Column<Advice>,
    constants: [Column<Fixed>; LANE_WIDTH],
    mode: Column<Fixed>,
    lookup_enable: Column<Fixed>,
    table: TableColumn,
    instance: Column<Instance>,
}

impl<F: PastaField> SigmaCircuit<F> {
    fn new(k: u32) -> Self {
        let rows = used_rows(k);
        let mds = lane_mds::<F>();
        let mut fixed_rng = data_rng(0xc0, k);
        let round_constants: Vec<[F; LANE_WIDTH]> = (0..rows)
            .map(|_| std::array::from_fn(|_| F::random(&mut fixed_rng)))
            .collect();
        let mut witness_rng = data_rng(0x5e, k);
        let mut states = Vec::with_capacity(rows);
        states.push(std::array::from_fn(|_| {
            std::array::from_fn(|_| F::random(&mut witness_rng))
        }));
        for row in 1..rows {
            let previous: [[F; LANE_WIDTH]; LANES] = states[row - 1];
            states.push(std::array::from_fn(|lane| {
                lane_round(&mds, &previous[lane], &round_constants[row - 1])
            }));
        }
        let bits = table_bits(k);
        let bytes = (0..rows)
            .map(|_| F::from(witness_rng.next_u64() & ((1_u64 << bits) - 1)))
            .collect();
        Self {
            k,
            witness: true,
            round_constants,
            states,
            bytes,
        }
    }

    fn public(&self) -> Vec<F> {
        vec![self.bytes[0]]
    }

    fn value(&self, value: F) -> Value<F> {
        if self.witness {
            Value::known(value)
        } else {
            Value::unknown()
        }
    }
}

impl<F: PastaField> Circuit<F> for SigmaCircuit<F> {
    type Config = SigmaConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self {
            witness: false,
            ..self.clone()
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> SigmaConfig {
        let lanes: [[Column<Advice>; LANE_WIDTH]; LANES] =
            std::array::from_fn(|_| std::array::from_fn(|_| meta.advice_column()));
        let bus = meta.advice_column();
        let base = meta.advice_column();
        let constants = std::array::from_fn(|_| meta.fixed_column());
        let mode = meta.fixed_column();
        let lookup_enable = meta.fixed_column();
        let table = meta.lookup_table_column();
        let instance = meta.instance_column(1);
        for column in [bus, base, lanes[0][0], lanes[1][0]] {
            meta.enable_equality(column);
        }
        meta.enable_equality(instance);
        let mds = lane_mds::<F>();
        for lane in lanes {
            meta.create_gate("sigma lane round", |cells| {
                let mode = cells.query_fixed(mode, Rotation::cur());
                let active = mode.clone() * (mode - Expression::Constant(F::ONE));
                let powers: [Expression<F>; LANE_WIDTH] = std::array::from_fn(|i| {
                    let shifted = cells.query_advice(lane[i], Rotation::cur())
                        + cells.query_fixed(constants[i], Rotation::cur());
                    let square = shifted.clone() * shifted.clone();
                    square.clone() * square * shifted
                });
                (0..LANE_WIDTH)
                    .map(|i| {
                        let mixed = (0..LANE_WIDTH)
                            .fold(Expression::Constant(F::ZERO), |sum, j| {
                                sum + Expression::Constant(mds[i][j]) * powers[j].clone()
                            });
                        active.clone() * (cells.query_advice(lane[i], Rotation::next()) - mixed)
                    })
                    .collect::<Vec<_>>()
            });
        }
        meta.lookup("sigma byte", |cells| {
            let enable = cells.query_fixed(lookup_enable, Rotation::cur());
            let value = cells.query_advice(base, Rotation::cur());
            vec![(enable * value, table)]
        });
        SigmaConfig {
            lanes,
            bus,
            base,
            constants,
            mode,
            lookup_enable,
            table,
            instance,
        }
    }

    fn synthesize(&self, config: SigmaConfig, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        let rows = used_rows(self.k);
        let table_size = 1_u64 << table_bits(self.k);
        layouter.assign_table(
            || "sigma byte table",
            |mut table| {
                for value in 0..table_size {
                    let offset = usize::try_from(value).map_err(|_| Error::Synthesis)?;
                    table.assign_cell(
                        || "byte",
                        config.table,
                        offset,
                        || Value::known(F::from(value)),
                    )?;
                }
                Ok(())
            },
        )?;
        let public_cell = layouter.assign_region(
            || "sigma rows",
            |mut region| {
                let mut public_cell: Option<Cell> = None;
                for row in 0..rows {
                    for (column, constant) in config.constants.iter().zip(self.round_constants[row])
                    {
                        region.assign_fixed(*column, row, constant)?;
                    }
                    let mode = if row + 1 < rows { 2_u64 } else { 0 };
                    region.assign_fixed(config.mode, row, F::from(mode))?;
                    region.assign_fixed(config.lookup_enable, row, F::ONE)?;
                    let mut heads = [None; LANES];
                    for (lane, columns) in config.lanes.iter().enumerate() {
                        for (i, column) in columns.iter().enumerate() {
                            let value = self.value(self.states[row][lane][i]);
                            let cell = region.assign_advice(*column, row, value)?.cell();
                            if i == 0 {
                                heads[lane] = Some(cell);
                            }
                        }
                    }
                    let bus_lane = usize::from(row % BUS_STRIDE == BUS_STRIDE / 2);
                    let bus_value = self.value(self.states[row][bus_lane][0]);
                    let bus_cell = region.assign_advice(config.bus, row, bus_value)?.cell();
                    if row % (BUS_STRIDE / 2) == 0 {
                        region
                            .constrain_equal(bus_cell, heads[bus_lane].ok_or(Error::Synthesis)?)?;
                    }
                    let byte_cell = region
                        .assign_advice(config.base, row, self.value(self.bytes[row]))?
                        .cell();
                    if row == 0 {
                        public_cell = Some(byte_cell);
                    }
                }
                public_cell.ok_or(Error::Synthesis)
            },
        )?;
        layouter.constrain_instance(public_cell, config.instance, 0)
    }
}

#[derive(Clone)]
struct WideCircuit<F: PastaField> {
    k: u32,
    witness: bool,
    rows: Vec<[F; WIDE_ADVICE]>,
}

#[derive(Clone, Copy)]
struct WideConfig {
    advice: [Column<Advice>; WIDE_ADVICE],
    product: Column<Fixed>,
    range: TableColumn,
    square: TableColumn,
    instance: Column<Instance>,
}

impl<F: PastaField> WideCircuit<F> {
    fn new(k: u32) -> Self {
        let used = used_rows(k);
        let bits = table_bits(k);
        let mut rng = data_rng(0x77, k);
        let start = F::random(&mut rng);
        let mut chains = [start; WIDE_GROUPS];
        let mut rows = Vec::with_capacity(used);
        for _ in 0..used {
            let u = F::from(small_nonzero(&mut rng, bits));
            let v = F::from(small_nonzero(&mut rng, bits));
            let v_squared = v.square();
            let w = F::random(&mut rng);
            let row = [
                chains[0], u, w, chains[1], v, w, chains[2], v, v_squared, chains[3], u, v_squared,
            ];
            for (group, chain) in chains.iter_mut().enumerate() {
                *chain = row[3 * group] * row[3 * group + 1] * row[3 * group + 2];
            }
            rows.push(row);
        }
        Self {
            k,
            witness: true,
            rows,
        }
    }

    fn public(&self) -> Vec<F> {
        vec![self.rows.last().expect("rows")[9]]
    }
}

impl<F: PastaField> Circuit<F> for WideCircuit<F> {
    type Config = WideConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self {
            witness: false,
            ..self.clone()
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> WideConfig {
        let advice: [Column<Advice>; WIDE_ADVICE] = std::array::from_fn(|_| meta.advice_column());
        for column in advice {
            meta.enable_equality(column);
        }
        let instance = meta.instance_column(1);
        meta.enable_equality(instance);
        let product = meta.fixed_column();
        let range = meta.lookup_table_column();
        let square = meta.lookup_table_column();
        for group in 0..WIDE_GROUPS {
            meta.create_gate("wide product", |cells| {
                let enable = cells.query_fixed(product, Rotation::cur());
                let x = cells.query_advice(advice[3 * group], Rotation::cur());
                let y = cells.query_advice(advice[3 * group + 1], Rotation::cur());
                let z = cells.query_advice(advice[3 * group + 2], Rotation::cur());
                let next = cells.query_advice(advice[3 * group], Rotation::next());
                vec![enable * (x * y * z - next)]
            });
        }
        meta.lookup("wide range", |cells| {
            vec![(cells.query_advice(advice[1], Rotation::cur()), range)]
        });
        meta.lookup("wide square", |cells| {
            vec![
                (cells.query_advice(advice[4], Rotation::cur()), range),
                (cells.query_advice(advice[8], Rotation::cur()), square),
            ]
        });
        WideConfig {
            advice,
            product,
            range,
            square,
            instance,
        }
    }

    fn synthesize(&self, config: WideConfig, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        let table_size = 1_u64 << table_bits(self.k);
        layouter.assign_table(
            || "wide tables",
            |mut table| {
                for value in 0..table_size {
                    let offset = usize::try_from(value).map_err(|_| Error::Synthesis)?;
                    let element = F::from(value);
                    table.assign_cell(
                        || "range",
                        config.range,
                        offset,
                        || Value::known(element),
                    )?;
                    table.assign_cell(
                        || "square",
                        config.square,
                        offset,
                        || Value::known(element.square()),
                    )?;
                }
                Ok(())
            },
        )?;
        let used = self.rows.len();
        let public_cell = layouter.assign_region(
            || "wide rows",
            |mut region| {
                let mut first_chains: Vec<Cell> = Vec::with_capacity(WIDE_GROUPS);
                let mut last_chain: Option<Cell> = None;
                for (row, values) in self.rows.iter().enumerate() {
                    let enable = if row + 1 < used { F::ONE } else { F::ZERO };
                    region.assign_fixed(config.product, row, enable)?;
                    let mut cells = Vec::with_capacity(WIDE_ADVICE);
                    for (column, value) in config.advice.iter().zip(values) {
                        let value = if self.witness {
                            Value::known(*value)
                        } else {
                            Value::unknown()
                        };
                        cells.push(region.assign_advice(*column, row, value)?.cell());
                    }
                    if row == 0 {
                        first_chains.extend((0..WIDE_GROUPS).map(|group| cells[3 * group]));
                    }
                    let (left, right) = match row % 4 {
                        0 => (1, 10),
                        1 => (4, 7),
                        2 => (2, 5),
                        _ => (8, 11),
                    };
                    region.constrain_equal(cells[left], cells[right])?;
                    last_chain = Some(cells[9]);
                }
                for pair in first_chains.windows(2) {
                    region.constrain_equal(pair[0], pair[1])?;
                }
                last_chain.ok_or(Error::Synthesis)
            },
        )?;
        layouter.constrain_instance(public_cell, config.instance, 0)
    }
}

/// The golden shape assertions: `(degree, permutation columns)`.
fn shape<F: PastaField, C: Circuit<F>>(circuit: &C) -> (usize, usize) {
    let (cs, _) = iroha_plonk::frontend::configure(circuit).expect("configure");
    (cs.degree(), cs.permutation().columns().len())
}

#[test]
fn golden_shapes_match_the_vendored_constants() {
    assert_eq!(shape(&SigmaCircuit::<Fp>::new(6)), (7, 5));
    assert_eq!(shape(&WideCircuit::<Fp>::new(8)), (4, WIDE_ADVICE + 1));
}

fn check_sigma<F: PastaField>(k: u32) {
    let circuit = SigmaCircuit::<F>::new(k);
    let synthesized = synthesize(&circuit, k, Some(&[circuit.public()])).expect("synthesis");
    let report = check(&synthesized.cs, &synthesized.tables, CheckMode::Strict).expect("check");
    assert!(report.is_satisfied(), "sigma k{k}: {report}");
}

#[test]
fn sigma_is_satisfied_in_strict_mode() {
    check_sigma::<Fp>(6);
    check_sigma::<Fq>(6);
    check_sigma::<Fp>(9);
}

#[test]
fn sigma_tampering_is_located() {
    let k = 6;
    let mut circuit = SigmaCircuit::<Fp>::new(k);
    circuit.states[10][1][2] += Fp::ONE;
    let synthesized = synthesize(&circuit, k, Some(&[circuit.public()])).expect("synthesis");
    let report = check(&synthesized.cs, &synthesized.tables, CheckMode::Strict).expect("check");
    let rows: Vec<(usize, usize)> = report
        .failures()
        .iter()
        .filter_map(|failure| match failure {
            CheckFailure::ConstraintNotSatisfied { gate, location, .. } => {
                Some((*gate, location.row))
            }
            _ => None,
        })
        .collect();
    // Lane 1 (gate 1) breaks where row 10 is the output (row 9) and the input
    // (row 10) of a round.
    assert!(rows.iter().all(|(gate, _)| *gate == 1), "{report}");
    assert!(
        rows.contains(&(1, 9)) && rows.contains(&(1, 10)),
        "{report}"
    );

    let mut circuit = SigmaCircuit::<Fp>::new(k);
    circuit.bytes[3] = Fp::from(1_000);
    let synthesized = synthesize(&circuit, k, Some(&[circuit.public()])).expect("synthesis");
    let report = check(&synthesized.cs, &synthesized.tables, CheckMode::Strict).expect("check");
    assert!(
        matches!(
            report.failures(),
            [CheckFailure::LookupInputMissing { location, .. }] if location.row == 3
        ),
        "{report}"
    );

    let circuit = SigmaCircuit::<Fp>::new(k);
    let synthesized =
        synthesize(&circuit, k, Some(&[vec![Fp::from(1_000_000)]])).expect("synthesis");
    let report = check(&synthesized.cs, &synthesized.tables, CheckMode::Strict).expect("check");
    assert!(
        report
            .failures()
            .iter()
            .all(|f| matches!(f, CheckFailure::CopyMismatch { .. }))
            && !report.is_satisfied(),
        "{report}"
    );
}

#[test]
fn wide_needs_halo2_compatible_mode() {
    let k = 8;
    let circuit = WideCircuit::<Fp>::new(k);
    let synthesized = synthesize(&circuit, k, Some(&[circuit.public()])).expect("synthesis");
    let compatible = check(
        &synthesized.cs,
        &synthesized.tables,
        CheckMode::Halo2Compatible,
    )
    .expect("check");
    assert!(compatible.is_satisfied(), "{compatible}");
    // Its always-on lookups read the unassigned advice rows between the
    // witness and the blinding rows, which the strict mode reports.
    let strict = check(&synthesized.cs, &synthesized.tables, CheckMode::Strict).expect("check");
    let used = used_rows(k);
    assert!(!strict.is_satisfied());
    assert!(strict.failures().iter().all(|failure| matches!(
        failure,
        CheckFailure::LookupPoisoned { table: false, location, .. } if location.row >= used
    )));
}

#[test]
fn wide_tampering_is_reported() {
    let k = 8;
    let mut circuit = WideCircuit::<Fp>::new(k);
    circuit.rows[5][2] += Fp::ONE;
    let synthesized = synthesize(&circuit, k, Some(&[circuit.public()])).expect("synthesis");
    let report = check(
        &synthesized.cs,
        &synthesized.tables,
        CheckMode::Halo2Compatible,
    )
    .expect("check");
    assert!(report.failures().iter().any(|failure| matches!(
        failure,
        CheckFailure::ConstraintNotSatisfied { gate: 0, location, .. } if location.row == 5
    )));
    // Row 2 copies column 2 to column 5; row 5 does not, so no copy failure.
    assert!(
        !report
            .failures()
            .iter()
            .any(|f| matches!(f, CheckFailure::CopyMismatch { .. })),
        "{report}"
    );
}

fn descriptor_bytes<F: PastaField, C: Circuit<F>>(
    circuit: &C,
    k: u32,
    curve: CurveV1,
    compress: bool,
) -> Vec<u8> {
    let synthesized = synthesize(&circuit.without_witnesses(), k, None).expect("keygen synthesis");
    let finalized = synthesized
        .cs
        .finalize(synthesized.tables.selectors(), compress)
        .expect("finalize");
    let descriptor = CircuitDescriptorV1::from_constraint_system(
        &finalized,
        DescriptorConfig {
            curve,
            k,
            transcript: TranscriptV1::Blake2bChallenge255,
            instance_mode: InstanceModeV1::Committed,
            proof_suffix: ProofSuffixV1::None,
        },
    )
    .expect("descriptor");
    let bytes = descriptor.encode().expect("encode");
    assert_eq!(CircuitDescriptorV1::decode(&bytes), Ok(descriptor));
    bytes
}

#[test]
fn golden_descriptors_are_deterministic() {
    let sigma = SigmaCircuit::<Fp>::new(6);
    let first = descriptor_bytes(&sigma, 6, CurveV1::Vesta, false);
    let second = descriptor_bytes(&SigmaCircuit::<Fp>::new(6), 6, CurveV1::Vesta, false);
    assert_eq!(first, second);
    let pallas = descriptor_bytes(&SigmaCircuit::<Fq>::new(6), 6, CurveV1::Pallas, false);
    assert_ne!(first, pallas);
    let wide = descriptor_bytes(&WideCircuit::<Fq>::new(8), 8, CurveV1::Pallas, true);
    let decoded = CircuitDescriptorV1::decode(&wide).expect("decode");
    assert_eq!(decoded.degree, 4);
    assert_eq!(decoded.permutation.len(), WIDE_ADVICE + 1);
    assert_eq!(decoded.lookups.len(), 2);
    // No selectors: the selector map is empty and adds no column.
    assert!(decoded.selectors.entries.is_empty());
    assert_eq!(decoded.selectors.first_column, decoded.num_fixed_columns);
    // Witness-free key generation gives the same descriptor as a witness run.
    let witness = WideCircuit::<Fq>::new(8);
    let synthesized = synthesize(&witness, 8, Some(&[witness.public()])).expect("witness");
    let finalized = synthesized
        .cs
        .finalize(synthesized.tables.selectors(), true)
        .expect("finalize");
    let from_witness = CircuitDescriptorV1::from_constraint_system(
        &finalized,
        DescriptorConfig {
            curve: CurveV1::Pallas,
            k: 8,
            transcript: TranscriptV1::Blake2bChallenge255,
            instance_mode: InstanceModeV1::Committed,
            proof_suffix: ProofSuffixV1::None,
        },
    )
    .expect("descriptor");
    assert_eq!(from_witness.encode().expect("encode"), wide);
    // Field constants in the descriptor are canonical encodings of the MDS.
    let mds = lane_mds::<Fp>();
    let sigma = CircuitDescriptorV1::decode(&first).expect("decode");
    let expected = mds[0][0].to_repr();
    assert!(sigma.gates[0].iter().flatten().any(|node| matches!(
        node,
        iroha_plonk::cs::descriptor::ExprNodeV1::Constant(bytes) if *bytes == expected
    )));
}
