//! Native frontend port of the captured Sigma/Wide golden circuit families.
//!
//! Fixed data, RNG draws, queries and copy order follow the independent original
//! baseline. The replay checks exact descriptors, keys, instances and proof bytes.
//! These are public synthetic test witnesses, never wallet or signing material.

use ff::Field;
use iroha_pasta::PastaField;
use rand_chacha::ChaCha20Rng;
use rand_core_06::{RngCore, SeedableRng};

use crate::{
    cs::{Advice, Column, ConstraintSystem, Expression, Fixed, Instance, Rotation, TableColumn},
    frontend::{Cell, Circuit, Error, Layouter, SimpleFloorPlanner, Value},
};

const RESERVED_ROWS: usize = 16;
const LANE_WIDTH: usize = 3;
const LANES: usize = 2;
const BUS_STRIDE: usize = 16;
const WIDE_ADVICE: usize = 12;
const WIDE_GROUPS: usize = WIDE_ADVICE / 3;

/// Number of usable circuit rows at `k`.
fn used_rows(k: u32) -> usize {
    (1_usize << k)
        .checked_sub(RESERVED_ROWS)
        .expect("k leaves rows after the reserved tail")
}

/// Bits of the lookup table at `k`: a byte table when it fits, otherwise a smaller one.
fn table_bits(k: u32) -> u32 {
    k.checked_sub(1).expect("k is positive").min(8)
}

/// Deterministic data stream for circuit constants and witnesses (never the prover RNG).
fn data_rng(label: u8, k: u32) -> ChaCha20Rng {
    let mut seed = [0_u8; 32];
    seed[0] = label;
    seed[1] = u8::try_from(k).expect("k fits a byte");
    seed[31] = 0x5a;
    ChaCha20Rng::from_seed(seed)
}

/// A small nonzero value below `2^bits`.
fn small_nonzero(rng: &mut ChaCha20Rng, bits: u32) -> u64 {
    let mask = (1_u64 << bits) - 1;
    (rng.next_u64() & mask).max(1)
}

/// Fixed lane MDS matrix, shared by `configure` and the witness.
fn lane_mds<F: Field>() -> [[F; LANE_WIDTH]; LANE_WIDTH] {
    let mut rng = data_rng(0xd5, 0);
    std::array::from_fn(|_| std::array::from_fn(|_| F::random(&mut rng)))
}

/// One Pow5 round: `next = M * (state + constants)^5`.
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

/// Sigma-shaped circuit: two Pow5-style lanes, an equality bus and a byte-lookup column.
#[derive(Clone)]
pub(super) struct SigmaCircuit<F: PastaField> {
    k: u32,
    witness: bool,
    round_constants: Vec<[F; LANE_WIDTH]>,
    states: Vec<[[F; LANE_WIDTH]; LANES]>,
    bytes: Vec<F>,
}

/// Columns of [`SigmaCircuit`].
#[derive(Clone, Copy)]
pub(super) struct SigmaConfig {
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
    /// Build the fixed data and witness for `k`.
    pub(super) fn new(k: u32) -> Self {
        let rows = used_rows(k);
        let mds = lane_mds::<F>();
        let mut fixed_rng = data_rng(0xc0, k);
        let round_constants = (0..rows)
            .map(|_| std::array::from_fn(|_| F::random(&mut fixed_rng)))
            .collect::<Vec<[F; LANE_WIDTH]>>();
        let mut witness_rng = data_rng(0x5e, k);
        let mut states = Vec::with_capacity(rows);
        states.push(std::array::from_fn(|_| {
            std::array::from_fn(|_| F::random(&mut witness_rng))
        }));
        for row in 1..rows {
            let previous: &[[F; LANE_WIDTH]; LANES] = &states[row - 1];
            let next = std::array::from_fn(|lane| {
                lane_round(&mds, &previous[lane], &round_constants[row - 1])
            });
            states.push(next);
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

    /// The single public input: the first base-column value.
    pub(super) fn public(&self) -> Vec<F> {
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
                // Mode 2 marks an active round; mode 0 disables the row.
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
                    let offset = usize::try_from(value).expect("table offset fits usize");
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
                    // The bus carries lane 0 except at the mid-stride row, which carries lane 1.
                    let bus_lane = usize::from(row % BUS_STRIDE == BUS_STRIDE / 2);
                    let bus_value = self.value(self.states[row][bus_lane][0]);
                    let bus_cell = region.assign_advice(config.bus, row, bus_value)?.cell();
                    if row % (BUS_STRIDE / 2) == 0 {
                        region.constrain_equal(
                            bus_cell,
                            heads[bus_lane].expect("every lane assigns its head"),
                        )?;
                    }
                    let byte_cell = region
                        .assign_advice(config.base, row, self.value(self.bytes[row]))?
                        .cell();
                    if row == 0 {
                        public_cell = Some(byte_cell);
                    }
                }
                Ok(public_cell.expect("row 0 is assigned"))
            },
        )?;
        layouter.constrain_instance(public_cell, config.instance, 0)?;
        Ok(())
    }
}

/// Wide degree-4 circuit: chained products in four column groups and two lookups.
#[derive(Clone)]
pub(super) struct WideCircuit<F: PastaField> {
    k: u32,
    witness: bool,
    /// Assigned advice values, one row of all twelve columns per circuit row.
    rows: Vec<[F; WIDE_ADVICE]>,
}

/// Columns of [`WideCircuit`].
#[derive(Clone, Copy)]
pub(super) struct WideConfig {
    advice: [Column<Advice>; WIDE_ADVICE],
    product: Column<Fixed>,
    range: TableColumn,
    square: TableColumn,
    instance: Column<Instance>,
}

impl<F: PastaField> WideCircuit<F> {
    /// Build the witness for `k`.
    ///
    /// Group `g` uses columns `(3g, 3g + 1, 3g + 2)` as `(x, y, z)` with
    /// `x_next = x * y * z`. Columns 1, 4, 7 and 10 hold small values, column 8 is
    /// the square of column 4 and the duplicated columns are copy-constrained.
    pub(super) fn new(k: u32) -> Self {
        let used = used_rows(k);
        let bits = table_bits(k);
        let mut rng = data_rng(0x77, k);
        let start = F::random(&mut rng);
        let mut chains = [start; WIDE_GROUPS];
        let mut rows = Vec::with_capacity(used);
        for _ in 0..used {
            let small = small_nonzero(&mut rng, bits);
            let other_small = small_nonzero(&mut rng, bits);
            let u = F::from(small);
            let v = F::from(other_small);
            let v_squared = v.square();
            let w = F::random(&mut rng);
            let row = [
                chains[0], u, w, // group 0
                chains[1], v, w, // group 1
                chains[2], v, v_squared, // group 2
                chains[3], u, v_squared, // group 3
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

    /// The single public input: the last group-3 chain value.
    pub(super) fn public(&self) -> Vec<F> {
        vec![self.rows.last().expect("wide circuit has rows")[9]]
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
        // Degree-one inputs keep the lookup argument at the circuit's degree 4.
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
                    let offset = usize::try_from(value).expect("table offset fits usize");
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
                    let mut assigned = Vec::with_capacity(WIDE_ADVICE);
                    for (column, value) in values.iter().enumerate() {
                        let value = if self.witness {
                            Value::known(*value)
                        } else {
                            Value::unknown()
                        };
                        assigned.push(
                            region
                                .assign_advice(config.advice[column], row, value)?
                                .cell(),
                        );
                    }
                    let cells: [Cell; WIDE_ADVICE] = assigned.try_into().expect("twelve columns");
                    if row == 0 {
                        first_chains.extend((0..WIDE_GROUPS).map(|group| cells[3 * group]));
                    }
                    // Rotate the duplicated pair that is copy-constrained on this row.
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
                Ok(last_chain.expect("wide circuit has rows"))
            },
        )?;
        layouter.constrain_instance(public_cell, config.instance, 0)?;
        Ok(())
    }
}
