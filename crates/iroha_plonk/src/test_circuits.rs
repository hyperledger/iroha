//! Small circuits shared by the prover and verifier unit tests.
//!
//! - [`Arithmetic`]: multiplication and scaled addition gates on alternating
//!   rows, a next-row link gate, constants, a public input and a public
//!   output (copy constraints between advice, fixed and instance columns);
//! - [`Lookups`]: a squaring gate, a two-column lookup of `(x, x^2)` and a
//!   `lookup_any` range check of `x + 1`, with no equality columns;
//! - [`Permutations`]: eight equality columns at degree 3, so every set holds
//!   one column and consecutive sets are linked at `omega^{-(b+1)}`;
//! - [`Forgeable`]: two advice columns under `s (a - b - 1)`, used by the
//!   malicious-prover case of soundness invariant S1.
//!
//! Every circuit takes a `tamper` row: when set, one witness cell on that
//! row is off by one, so the constraint checker and the verifier must both
//! reject.

use iroha_pasta::{PastaCurve, PastaField, msm::MemoryBudget, poseidon::PoseidonField};

use crate::{
    cs::{
        Advice, Column, ConstraintSystem, Expression, Fixed, Instance, InstanceModeV1,
        ProofSuffixV1, Rotation, Selector, TableColumn, TranscriptV1,
    },
    frontend::{Circuit, Error, Layouter, SimpleFloorPlanner, Value},
    keys::{KeygenConfig, ProvingKey, keygen_pk},
    pcs::ipa::PinnedParams,
    prover::{ProverConfig, ProverError, ProverRandomness, prove_circuit},
};

/// The MSM budget of the tests.
pub const BUDGET: MemoryBudget = MemoryBudget::DEFAULT;

/// A protocol configuration: transcript, instance mode, suffix and selector
/// compression.
pub type Choice = (TranscriptV1, InstanceModeV1, ProofSuffixV1, bool);

/// Configurations that together cover every protocol option.
pub const CHOICES: [Choice; 4] = [
    (
        TranscriptV1::Blake2bChallenge255,
        InstanceModeV1::Committed,
        ProofSuffixV1::None,
        true,
    ),
    (
        TranscriptV1::KagemushaPoseidonRp57,
        InstanceModeV1::Direct,
        ProofSuffixV1::FoldedGenerator,
        true,
    ),
    (
        TranscriptV1::Blake2bChallenge255,
        InstanceModeV1::Direct,
        ProofSuffixV1::FoldedGenerator,
        false,
    ),
    (
        TranscriptV1::KagemushaPoseidonRp57,
        InstanceModeV1::Committed,
        ProofSuffixV1::None,
        false,
    ),
];

/// The key-generation configuration of a choice.
pub fn keygen_config(choice: Choice) -> KeygenConfig {
    let (transcript, instance_mode, proof_suffix, compress) = choice;
    let mut config = KeygenConfig::new(transcript);
    config.instance_mode = instance_mode;
    config.proof_suffix = proof_suffix;
    config.compress_selectors = compress;
    config
}

/// Parameters and a proving key.
pub struct Setup<C: PastaCurve> {
    /// The parameters at [`K`].
    pub params: PinnedParams<C>,
    /// The proving key.
    pub pk: ProvingKey<C>,
}

/// Derives the parameters and generates the proving key of `circuit`.
pub fn setup<C: PastaCurve, Ci: Circuit<C::ScalarExt>>(circuit: &Ci, choice: Choice) -> Setup<C> {
    let params = PinnedParams::<C>::derive(K).expect("params");
    let pk = keygen_pk(
        &params,
        &circuit.without_witnesses(),
        &keygen_config(choice),
    )
    .expect("proving key");
    Setup { params, pk }
}

impl<C: PastaCurve> Setup<C>
where
    C::ScalarExt: PoseidonField,
    C::Base: PoseidonField,
{
    /// Proves `circuit` with a fixed `ChaCha20` seed.
    pub fn prove<Ci: Circuit<C::ScalarExt>>(
        &self,
        circuit: &Ci,
        instances: &[Vec<C::ScalarExt>],
        seed: u8,
    ) -> Result<Vec<u8>, ProverError> {
        prove_circuit(
            &self.params,
            &self.pk,
            circuit,
            instances,
            ProverRandomness::fixed_seed_for_tests([seed; 32]),
            ProverConfig::default(),
        )
    }

    /// Verifies a proof in full.
    pub fn verify(
        &self,
        instances: &[Vec<C::ScalarExt>],
        proof: &[u8],
    ) -> Result<(), crate::verifier::VerifyError> {
        crate::verifier::verify_full(
            &self.params,
            self.pk.binding(),
            self.pk.vk(),
            instances,
            proof,
            BUDGET,
        )
    }
}

/// The `k` of every test circuit.
pub const K: u32 = 6;

/// Columns of [`Arithmetic`].
#[derive(Clone, Copy, Debug)]
pub struct ArithmeticConfig {
    a: Column<Advice>,
    b: Column<Advice>,
    c: Column<Advice>,
    coeff: Column<Fixed>,
    instance: Column<Instance>,
    mul: Selector,
    add: Selector,
    link: Selector,
}

/// A chain `c_i = a_i b_i` (even rows) or `c_i = a_i + 5 b_i` (odd rows),
/// `a_{i+1} = c_i`, starting from the public input and ending at the public
/// output.
#[derive(Clone, Copy, Debug)]
pub struct Arithmetic {
    /// The public input `a_0`.
    pub start: u64,
    /// Rows of the chain.
    pub rows: usize,
    /// A row whose `c` is off by one.
    pub tamper: Option<usize>,
}

impl Arithmetic {
    /// The honest chain values `(a, b, c)` per row.
    fn chain<F: PastaField>(&self) -> Vec<(F, F, F)> {
        let mut a = F::from(self.start);
        (0..self.rows)
            .map(|row| {
                let b = F::from(3 + row as u64);
                let c = if row % 2 == 0 {
                    a * b
                } else {
                    a + F::from(5) * b
                };
                let out = (a, b, c);
                a = c;
                out
            })
            .collect()
    }

    /// The instances `[[a_0, c_last]]`.
    pub fn instances<F: PastaField>(&self) -> Vec<Vec<F>> {
        let last = self.chain::<F>().last().map_or(F::ZERO, |row| row.2);
        vec![vec![F::from(self.start), last]]
    }
}

impl<F: PastaField> Circuit<F> for Arithmetic {
    type Config = ArithmeticConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        *self
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> ArithmeticConfig {
        let a = meta.advice_column();
        let b = meta.advice_column();
        let c = meta.advice_column();
        let constants = meta.fixed_column();
        meta.enable_constant(constants);
        let coeff = meta.fixed_column();
        let instance = meta.instance_column(2);
        meta.enable_equality(a);
        meta.enable_equality(b);
        meta.enable_equality(c);
        meta.enable_equality(instance);
        let mul = meta.selector();
        let add = meta.selector();
        let link = meta.selector();
        meta.create_gate("mul", |cells| {
            let enabled = cells.query_selector(mul);
            let a = cells.query_advice(a, Rotation::cur());
            let b = cells.query_advice(b, Rotation::cur());
            let c = cells.query_advice(c, Rotation::cur());
            vec![enabled * (a * b - c)]
        });
        meta.create_gate("add", |cells| {
            let enabled = cells.query_selector(add);
            let a = cells.query_advice(a, Rotation::cur());
            let b = cells.query_advice(b, Rotation::cur());
            let coeff = cells.query_fixed(coeff, Rotation::cur());
            let c = cells.query_advice(c, Rotation::cur());
            vec![enabled * ((a + coeff * b - c) * F::from(7))]
        });
        meta.create_gate("link", |cells| {
            let enabled = cells.query_selector(link);
            let next = cells.query_advice(a, Rotation::next());
            let c = cells.query_advice(c, Rotation::cur());
            vec![("link", enabled * (next - c))]
        });
        ArithmeticConfig {
            a,
            b,
            c,
            coeff,
            instance,
            mul,
            add,
            link,
        }
    }

    fn synthesize(
        &self,
        config: ArithmeticConfig,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let chain = self.chain::<F>();
        let last = layouter.assign_region(
            || "chain",
            |mut region| {
                let mut last = None;
                for (row, (a, b, c)) in chain.iter().enumerate() {
                    if row % 2 == 0 {
                        config.mul.enable(&mut region, row)?;
                    } else {
                        config.add.enable(&mut region, row)?;
                        region.assign_fixed(config.coeff, row, F::from(5))?;
                    }
                    if row + 1 < chain.len() {
                        config.link.enable(&mut region, row)?;
                    }
                    if row == 0 {
                        region.assign_advice_from_instance(
                            || "start",
                            config.instance,
                            0,
                            config.a,
                            0,
                        )?;
                        region.assign_advice_from_constant(|| "three", config.b, 0, *b)?;
                    } else {
                        region.assign_advice(config.a, row, Value::known(*a))?;
                        region.assign_advice(config.b, row, Value::known(*b))?;
                    }
                    let c = if self.tamper == Some(row) {
                        *c + F::ONE
                    } else {
                        *c
                    };
                    last = Some(region.assign_advice(config.c, row, Value::known(c))?.cell());
                }
                last.ok_or(Error::Synthesis)
            },
        )?;
        layouter.constrain_instance(last, config.instance, 1)
    }
}

/// Columns of [`Lookups`].
#[derive(Clone, Copy, Debug)]
pub struct LookupsConfig {
    x: Column<Advice>,
    y: Column<Advice>,
    square: Selector,
    lookup: Selector,
    values: TableColumn,
    squares: TableColumn,
}

/// `y = x^2` checked by a gate and by a lookup into the table `(i, i^2)`,
/// `i < 16`, plus a range check of `x + 1` against the first table column.
#[derive(Clone, Copy, Debug)]
pub struct Lookups {
    /// Rows of witness values.
    pub rows: usize,
    /// A row whose `y` is off by one.
    pub tamper: Option<usize>,
    /// Use `x = 15` on row 0, which fails the range check of `x + 1`.
    pub out_of_range: bool,
    /// Shifts every `x`: equal shapes, different witnesses.
    pub offset: u64,
}

impl<F: PastaField> Circuit<F> for Lookups {
    type Config = LookupsConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        *self
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> LookupsConfig {
        let x = meta.advice_column();
        let y = meta.advice_column();
        let square = meta.selector();
        let lookup = meta.complex_selector();
        let values = meta.lookup_table_column();
        let squares = meta.lookup_table_column();
        meta.create_gate("square", |cells| {
            let enabled = cells.query_selector(square);
            let x = cells.query_advice(x, Rotation::cur());
            let y = cells.query_advice(y, Rotation::cur());
            vec![enabled * (y - x.clone() * x)]
        });
        meta.lookup("pairs", |cells| {
            let enabled = cells.query_selector(lookup);
            let x = cells.query_advice(x, Rotation::cur());
            let y = cells.query_advice(y, Rotation::cur());
            vec![(enabled.clone() * x, values), (enabled * y, squares)]
        });
        meta.lookup_any("range", |cells| {
            let enabled = cells.query_selector(lookup);
            let x = cells.query_advice(x, Rotation::cur());
            let table = cells.query_fixed(values.inner(), Rotation::cur());
            vec![(enabled * (x + Expression::Constant(F::ONE)), table)]
        });
        LookupsConfig {
            x,
            y,
            square,
            lookup,
            values,
            squares,
        }
    }

    fn synthesize(
        &self,
        config: LookupsConfig,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_table(
            || "squares",
            |mut table| {
                for i in 0..16_u64 {
                    let row = usize::try_from(i).map_err(|_| Error::Synthesis)?;
                    table.assign_cell(|| "i", config.values, row, || Value::known(F::from(i)))?;
                    table.assign_cell(
                        || "i^2",
                        config.squares,
                        row,
                        || Value::known(F::from(i * i)),
                    )?;
                }
                Ok(())
            },
        )?;
        layouter.assign_region(
            || "values",
            |mut region| {
                for row in 0..self.rows {
                    let x = if self.out_of_range && row == 0 {
                        15
                    } else {
                        (row as u64 * 5 + 2 + self.offset) % 15
                    };
                    let y = if self.tamper == Some(row) {
                        x * x + 1
                    } else {
                        x * x
                    };
                    config.square.enable(&mut region, row)?;
                    region.enable_selector(|| "lookup", &config.lookup, row)?;
                    region.assign_advice(config.x, row, Value::known(F::from(x)))?;
                    region.assign_advice(config.y, row, Value::known(F::from(y)))?;
                }
                Ok(())
            },
        )
    }
}

/// Columns of [`Permutations`].
#[derive(Clone, Debug)]
pub struct PermutationsConfig {
    columns: Vec<Column<Advice>>,
    instance: Column<Instance>,
    sum: Selector,
}

/// Six advice columns, a constants column and an instance column, all
/// equality-enabled at degree 3 (one column per permutation set, eight
/// sets). Row `r` holds `c_j = 10 + r + j`; a gate checks `c_0 - c_1 + 1 =
/// 0` and `c_1 - c_2 + 1 = 0`, every `c_{j+1}` of row `r` is copied from `c_j` of row `r + 1`, the
/// first cell is a constant and three cells are public.
#[derive(Clone, Copy, Debug)]
pub struct Permutations {
    /// Rows of the grid.
    pub rows: usize,
    /// A row whose last column is off by one (breaking a copy cycle).
    pub tamper: Option<usize>,
}

impl Permutations {
    /// The value of column `j` on row `r`.
    fn value<F: PastaField>(row: usize, column: usize) -> F {
        F::from(10 + row as u64 + column as u64)
    }

    /// The instances: the first and last values of column 0 and the last of
    /// column 5.
    pub fn instances<F: PastaField>(&self) -> Vec<Vec<F>> {
        let last = self.rows - 1;
        vec![vec![
            Self::value(0, 0),
            Self::value(last, 0),
            Self::value(last, 5),
        ]]
    }
}

impl<F: PastaField> Circuit<F> for Permutations {
    type Config = PermutationsConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        *self
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> PermutationsConfig {
        let columns: Vec<Column<Advice>> = (0..6).map(|_| meta.advice_column()).collect();
        let constants = meta.fixed_column();
        meta.enable_constant(constants);
        let instance = meta.instance_column(3);
        for column in &columns {
            meta.enable_equality(*column);
        }
        meta.enable_equality(instance);
        let sum = meta.selector();
        let (c0, c1, c2) = (columns[0], columns[1], columns[2]);
        meta.create_gate("step", |cells| {
            let enabled = cells.query_selector(sum);
            let c0 = cells.query_advice(c0, Rotation::cur());
            let c1 = cells.query_advice(c1, Rotation::cur());
            let c2 = cells.query_advice(c2, Rotation::cur());
            // c_j = 10 + r + j: consecutive columns differ by one.
            vec![
                enabled.clone() * (c0 - c1.clone() + Expression::Constant(F::ONE)),
                enabled * (c1 - c2 + Expression::Constant(F::ONE)),
            ]
        });
        PermutationsConfig {
            columns,
            instance,
            sum,
        }
    }

    fn synthesize(
        &self,
        config: PermutationsConfig,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let rows = self.rows;
        let cells = layouter.assign_region(
            || "grid",
            |mut region| {
                let mut grid = Vec::with_capacity(rows);
                for row in 0..rows {
                    config.sum.enable(&mut region, row)?;
                    let mut cells = Vec::with_capacity(config.columns.len());
                    for (j, column) in config.columns.iter().enumerate() {
                        let mut value = Self::value::<F>(row, j);
                        if self.tamper == Some(row) && j == 5 {
                            value += F::ONE;
                        }
                        cells.push(
                            region
                                .assign_advice(*column, row, Value::known(value))?
                                .cell(),
                        );
                    }
                    grid.push(cells);
                }
                // c_{j+1}[r] = c_j[r + 1]: long copy cycles across every set.
                for row in 0..rows - 1 {
                    for j in 0..config.columns.len() - 1 {
                        region.constrain_equal(grid[row][j + 1], grid[row + 1][j])?;
                    }
                }
                region.constrain_constant(grid[0][0], Self::value::<F>(0, 0))?;
                Ok(grid)
            },
        )?;
        let last = rows - 1;
        layouter.constrain_instance(cells[0][0], config.instance, 0)?;
        layouter.constrain_instance(cells[last][0], config.instance, 1)?;
        layouter.constrain_instance(cells[last][5], config.instance, 2)
    }
}

/// Columns of [`Forgeable`].
#[derive(Clone, Copy, Debug)]
pub struct ForgeableConfig {
    pub a: Column<Advice>,
    pub b: Column<Advice>,
    selector: Selector,
}

/// `s (a - b - 1) = 0` on the first `rows` rows.
#[derive(Clone, Copy, Debug)]
pub struct Forgeable {
    /// Enabled rows.
    pub rows: usize,
}

impl<F: PastaField> Circuit<F> for Forgeable {
    type Config = ForgeableConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        *self
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> ForgeableConfig {
        let a = meta.advice_column();
        let b = meta.advice_column();
        let selector = meta.selector();
        meta.create_gate("offset", |cells| {
            let enabled = cells.query_selector(selector);
            let a = cells.query_advice(a, Rotation::cur());
            let b = cells.query_advice(b, Rotation::cur());
            vec![enabled * (a - b - Expression::Constant(F::ONE))]
        });
        ForgeableConfig { a, b, selector }
    }

    fn synthesize(
        &self,
        config: ForgeableConfig,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "offset",
            |mut region| {
                for row in 0..self.rows {
                    config.selector.enable(&mut region, row)?;
                    let a = F::from(100 + row as u64);
                    region.assign_advice(config.a, row, Value::known(a))?;
                    region.assign_advice(config.b, row, Value::known(a - F::ONE))?;
                }
                Ok(())
            },
        )
    }
}
