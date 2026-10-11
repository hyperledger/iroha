//! The RP57 width-3 Pow5 Poseidon permutation chip (port of the M8 custom
//! lane, `g3_proof_scaling_measurement_tests.rs` `mod m8`).
//!
//! # Layout
//!
//! A lane has three state columns `s0, s1, s2` and one equality-enabled
//! auxiliary column `x`. A permutation occupies one block of 37 rows
//! ([`ROWS_PER_PERMUTATION`], so 148 cells), and row `o` of the block
//! computes:
//!
//! | offset | rounds | gate |
//! | --- | --- | --- |
//! | 0 | 0 (full), absorbing `x[0], x[1]` into words 1 and 2 | absorb, or full |
//! | 1-3 | 1-3 (full) | full |
//! | 4-31 | two partial rounds per row, `4 + 2(o - 4)` and the next | pair |
//! | 32 | 60 (partial) | partial |
//! | 33-36 | 61-64 (full) | full, or squeeze at 36 |
//!
//! Each gate maps the state on its row to the state on the next row, so the
//! state entering block `B + 1` is the state leaving block `B` (the sponge
//! chains through rotations, without copies). The pair gate keeps degree 6
//! by holding the first partial round's S-box output in `x`: with
//! `mid = (s0 + a0)^5`, `first = [mid, s1 + a1, s2 + a2]` and
//! `second = MDS first + b`, it constrains `next = MDS [second0^5, second1,
//! second2]`. The squeeze gate replaces the last full round's next-row state
//! by `x = (MDS sbox)[1]`, the sponge output, so a hash of `N` permutations
//! uses exactly `N` blocks.
//!
//! Round constants live in six fixed columns (`a` for the row's first
//! round, `b` for a pair's second), written at the same offsets of every
//! block. Blocks start at multiples of 37 from row 0, so several lanes may
//! share one set of round-constant columns (the M8 layout). The state that
//! enters a hash is pinned by a start gate `q_start (s_i - c_i)` whose
//! constants `c` are part of the circuit description: the raw sponge state
//! `[2^64, 0, 0]` and any configured domain-prefixed state.
//!
//! Ordinary gates have degree at most six; compact phase enables raise the
//! maximum to nine. The columns are queried at rotations 0
//! and +1, inside the default blinding budget.
//!
//! # Native reference
//!
//! [`iroha_pasta::poseidon::permute`]: the state leaving a block is that
//! permutation of the state entering it plus the absorbed words.

use iroha_pasta::{
    PastaField,
    poseidon::{FULL_ROUNDS, PARTIAL_ROUNDS, PoseidonField, PoseidonParams, ROUNDS, WIDTH},
};
use iroha_plonk::{
    cs::{Advice, Column, ConstraintSystem, Expression, Fixed, Rotation, Selector},
    frontend::{Error, Region, Value},
};

use crate::{
    cells::{Word, assign_constant, assign_word, copy_word},
    phase::{Enable, PhaseColumns},
};

/// Rows of one permutation block: 4 full, 28 pair, 1 partial, 4 full.
pub const ROWS_PER_PERMUTATION: usize = 37;
/// Advice columns of one lane: the state and the auxiliary column.
pub const LANE_COLUMNS: usize = WIDTH + 1;
/// Advice cells of one permutation (148, the M8 inventory).
pub const CELLS_PER_PERMUTATION: usize = ROWS_PER_PERMUTATION * LANE_COLUMNS;

/// Full rounds on each side of the partial rounds.
const HALF_FULL: usize = FULL_ROUNDS / 2;
/// Rows holding two partial rounds each.
const PAIR_ROWS: usize = PARTIAL_ROUNDS / 2;
/// The offset of the single partial round.
const SINGLE_PARTIAL: usize = HALF_FULL + PAIR_ROWS;
/// The offset of the last round.
const LAST_ROUND: usize = ROWS_PER_PERMUTATION - 1;

const _: () = assert!(PARTIAL_ROUNDS == 2 * PAIR_ROWS + 1);
const _: () = assert!(SINGLE_PARTIAL + 1 + HALF_FULL == ROWS_PER_PERMUTATION);
const _: () = assert!(HALF_FULL + PARTIAL_ROUNDS + HALF_FULL == ROUNDS);

/// The round a block row computes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RowRound {
    /// One full round.
    Full(usize),
    /// Two partial rounds, this one and the next.
    Pair(usize),
    /// One partial round.
    Partial(usize),
}

impl RowRound {
    /// The round(s) of block row `offset < 37`.
    const fn at(offset: usize) -> Self {
        if offset < HALF_FULL {
            Self::Full(offset)
        } else if offset < SINGLE_PARTIAL {
            Self::Pair(HALF_FULL + 2 * (offset - HALF_FULL))
        } else if offset == SINGLE_PARTIAL {
            Self::Partial(HALF_FULL + PARTIAL_ROUNDS - 1)
        } else {
            Self::Full(offset - SINGLE_PARTIAL - 1 + HALF_FULL + PARTIAL_ROUNDS)
        }
    }
}

/// Whether `round` is a full round.
const fn is_full_round(round: usize) -> bool {
    round < HALF_FULL || round >= HALF_FULL + PARTIAL_ROUNDS
}

/// `x^5`.
fn pow5<F: PastaField>(x: F) -> F {
    x.square().square() * x
}

/// One native round: add constants, S-box (all words or word 0), MDS.
fn round<F: PastaField>(params: &PoseidonParams<F>, state: [F; WIDTH], round: usize) -> [F; WIDTH] {
    let constants = params.round_constants()[round];
    let mut input: [F; WIDTH] = core::array::from_fn(|i| state[i] + constants[i]);
    for (index, word) in input.iter_mut().enumerate() {
        if index == 0 || is_full_round(round) {
            *word = pow5(*word);
        }
    }
    mds_apply(params.mds(), &input)
}

/// `MDS v`.
fn mds_apply<F: PastaField>(mds: &[[F; WIDTH]; WIDTH], v: &[F; WIDTH]) -> [F; WIDTH] {
    core::array::from_fn(|i| mds[i][0] * v[0] + mds[i][1] * v[1] + mds[i][2] * v[2])
}

/// `x^5` as an expression.
fn pow5_expression<F: Clone>(x: Expression<F>) -> Expression<F> {
    let square = x.clone() * x.clone();
    square.clone() * square * x
}

/// `sum_j row[j] values[j]` as an expression.
fn mds_row<F: PastaField>(row: &[F; WIDTH], values: &[Expression<F>; WIDTH]) -> Expression<F> {
    values[0].clone() * row[0] + values[1].clone() * row[1] + values[2].clone() * row[2]
}

/// The four advice columns of one lane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pow5Columns {
    /// The state columns `s0, s1, s2`.
    pub state: [Column<Advice>; WIDTH],
    /// The auxiliary column: absorbed inputs, pair S-box outputs and the
    /// squeezed output. It is equality-enabled by [`Pow5Config::configure`].
    pub aux: Column<Advice>,
}

impl Pow5Columns {
    /// Allocates four new advice columns.
    pub fn allocate<F: PastaField>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            state: core::array::from_fn(|_| meta.advice_column()),
            aux: meta.advice_column(),
        }
    }
}

/// The six round-constant columns, shareable between lanes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoundConstantColumns {
    a: [Column<Fixed>; WIDTH],
    b: [Column<Fixed>; WIDTH],
}

impl RoundConstantColumns {
    /// Uses six existing fixed columns (`a0..a2`, then `b0..b2`). A caller
    /// sharing them with another gated chip must use disjoint assignment rows.
    #[must_use]
    pub const fn from_columns(columns: [Column<Fixed>; 6]) -> Self {
        Self {
            a: [columns[0], columns[1], columns[2]],
            b: [columns[3], columns[4], columns[5]],
        }
    }

    /// Allocates six new fixed columns.
    pub fn allocate<F: PastaField>(meta: &mut ConstraintSystem<F>) -> Self {
        Self::from_columns(core::array::from_fn(|_| meta.fixed_column()))
    }
}

/// Four round selectors that aligned Pow5 lanes may share.
///
/// Every participating lane must enable absorption, full rounds, paired
/// partial rounds and single partial rounds on the same rows. In particular,
/// the lanes need matching permutation spans, absorption modes and
/// squeeze/continuation boundaries. Sharing activates every lane's round
/// constraints wherever any participant enables the selector; it does not
/// pad missing work. Start-state and squeeze selectors remain lane-local.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharedRoundSelectors {
    absorb: Selector,
    full: Selector,
    pair: Selector,
    partial: Selector,
}

impl SharedRoundSelectors {
    /// Allocates one set of round selectors in the participating lanes'
    /// constraint system. Reusing this bundle is an explicit opt-in to the
    /// common row schedule documented on [`Self`].
    pub fn allocate<F: PastaField>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            absorb: meta.selector(),
            full: meta.selector(),
            pair: meta.selector(),
            partial: meta.selector(),
        }
    }
}

/// A start gate: its selector and the state it pins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Start<F> {
    selector: Enable,
    state: [F; WIDTH],
}

/// Columns, selectors and start states of one Pow5 lane.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pow5Config<F> {
    lane: Pow5Columns,
    round_constants: RoundConstantColumns,
    q_absorb: Enable,
    q_full: Enable,
    q_pair: Enable,
    q_partial: Enable,
    q_squeeze: Enable,
    starts: Vec<Start<F>>,
}

impl<F: PoseidonField> Pow5Config<F> {
    /// Configures a lane on `lane` with the round constants in
    /// `round_constants` and one start gate per distinct state of
    /// `initial_states`.
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        lane: Pow5Columns,
        round_constants: RoundConstantColumns,
        initial_states: &[[F; WIDTH]],
    ) -> Self {
        meta.enable_equality(lane.aux);
        let shared = SharedRoundSelectors::allocate(meta);
        Self::configure_with_shared_round_selectors(
            meta,
            lane,
            round_constants,
            initial_states,
            shared,
        )
    }

    /// Configures a lane using four explicitly shared round selectors.
    ///
    /// All lanes receiving `shared` must have the common row schedule
    /// documented on [`SharedRoundSelectors`]. Each lane keeps its own
    /// squeeze and start-state selectors, constraints and witnesses. Use
    /// [`Self::configure`] when lane schedules may differ.
    pub fn configure_with_shared_round_selectors(
        meta: &mut ConstraintSystem<F>,
        lane: Pow5Columns,
        round_constants: RoundConstantColumns,
        initial_states: &[[F; WIDTH]],
        shared: SharedRoundSelectors,
    ) -> Self {
        let enables = [
            shared.absorb.into(),
            shared.full.into(),
            shared.pair.into(),
            shared.partial.into(),
            meta.selector().into(),
        ];
        Self::configure_enabled(meta, lane, round_constants, initial_states, &enables, None)
    }

    /// Shares the compact phase payloads with Glue and ECC on disjoint rows.
    /// Only the supplied raw initial state is configured; domain framing is
    /// absorbed explicitly. The resulting gates have degree at most nine.
    pub fn configure_phased(
        meta: &mut ConstraintSystem<F>,
        lane: Pow5Columns,
        phases: PhaseColumns,
        initial: [F; WIDTH],
    ) -> Self {
        let enables = [
            phases.enable(2, Some((3, 1, 2))),
            phases.enable(2, Some((3, 2, 2))),
            phases.enable(3, None),
            phases.enable(2, Some((4, 1, 2))),
            phases.enable(2, Some((4, 2, 2))),
        ];
        Self::configure_enabled(
            meta,
            lane,
            RoundConstantColumns::from_columns(phases.coefficients()),
            &[initial],
            &enables,
            Some(phases.enable(2, Some((5, 1, 2)))),
        )
    }

    fn configure_enabled(
        meta: &mut ConstraintSystem<F>,
        lane: Pow5Columns,
        round_constants: RoundConstantColumns,
        initial_states: &[[F; WIDTH]],
        enables: &[Enable; 5],
        start_enable: Option<Enable>,
    ) -> Self {
        meta.enable_equality(lane.aux);
        let mds = *F::rp57().mds();
        let [q_absorb, q_full, q_pair, q_partial, q_squeeze] = *enables;
        let Pow5Columns { state, aux } = lane;
        let RoundConstantColumns { a: rc_a, b: rc_b } = round_constants;

        for (name, selector, absorb) in [
            ("pow5 absorb and full round", q_absorb, true),
            ("pow5 full round", q_full, false),
        ] {
            meta.create_gate(name, |cells| {
                let q = selector.query(cells);
                let s = state.map(|column| cells.query_advice(column, Rotation::cur()));
                let next = state.map(|column| cells.query_advice(column, Rotation::next()));
                let a = rc_a.map(|column| cells.query_fixed(column, Rotation::cur()));
                let [s0, s1, s2] = s;
                let [a0, a1, a2] = a;
                let input = if absorb {
                    let x1 = cells.query_advice(aux, Rotation::cur());
                    let x2 = cells.query_advice(aux, Rotation::next());
                    [s0 + a0, s1 + x1 + a1, s2 + x2 + a2]
                } else {
                    [s0 + a0, s1 + a1, s2 + a2]
                };
                let sbox = input.map(pow5_expression);
                (0..WIDTH)
                    .map(|i| q.clone() * (next[i].clone() - mds_row(&mds[i], &sbox)))
                    .collect::<Vec<_>>()
            });
        }
        meta.create_gate("pow5 two partial rounds", |cells| {
            let q = q_pair.query(cells);
            let s = state.map(|column| cells.query_advice(column, Rotation::cur()));
            let next = state.map(|column| cells.query_advice(column, Rotation::next()));
            let a = rc_a.map(|column| cells.query_fixed(column, Rotation::cur()));
            let b = rc_b.map(|column| cells.query_fixed(column, Rotation::cur()));
            let mid = cells.query_advice(aux, Rotation::cur());
            let [s0, s1, s2] = s;
            let [a0, a1, a2] = a;
            let first = [mid.clone(), s1 + a1, s2 + a2];
            let second: [Expression<F>; WIDTH] =
                core::array::from_fn(|i| mds_row(&mds[i], &first) + b[i].clone());
            let [second0, second1, second2] = second;
            let sbox = [pow5_expression(second0), second1, second2];
            let mut polys = vec![q.clone() * (mid - pow5_expression(s0 + a0))];
            polys.extend(
                (0..WIDTH).map(|i| q.clone() * (next[i].clone() - mds_row(&mds[i], &sbox))),
            );
            polys
        });
        meta.create_gate("pow5 partial round", |cells| {
            let q = q_partial.query(cells);
            let s = state.map(|column| cells.query_advice(column, Rotation::cur()));
            let next = state.map(|column| cells.query_advice(column, Rotation::next()));
            let a = rc_a.map(|column| cells.query_fixed(column, Rotation::cur()));
            let [s0, s1, s2] = s;
            let [a0, a1, a2] = a;
            let sbox = [pow5_expression(s0 + a0), s1 + a1, s2 + a2];
            (0..WIDTH)
                .map(|i| q.clone() * (next[i].clone() - mds_row(&mds[i], &sbox)))
                .collect::<Vec<_>>()
        });
        meta.create_gate("pow5 squeeze round", |cells| {
            let q = q_squeeze.query(cells);
            let s = state.map(|column| cells.query_advice(column, Rotation::cur()));
            let a = rc_a.map(|column| cells.query_fixed(column, Rotation::cur()));
            let output = cells.query_advice(aux, Rotation::cur());
            let [s0, s1, s2] = s;
            let [a0, a1, a2] = a;
            let sbox = [s0 + a0, s1 + a1, s2 + a2].map(pow5_expression);
            vec![("x - (MDS sbox)[1]", q * (output - mds_row(&mds[1], &sbox)))]
        });
        let mut starts: Vec<Start<F>> = Vec::new();
        for initial in initial_states {
            if starts.iter().any(|start| start.state == *initial) {
                continue;
            }
            let selector = start_enable.unwrap_or_else(|| meta.selector().into());
            let initial = *initial;
            meta.create_gate("pow5 start state", |cells| {
                let q = selector.query(cells);
                (0..WIDTH)
                    .map(|i| {
                        let s = cells.query_advice(state[i], Rotation::cur());
                        q.clone() * (s - Expression::Constant(initial[i]))
                    })
                    .collect::<Vec<_>>()
            });
            starts.push(Start {
                selector,
                state: initial,
            });
        }
        Self {
            lane,
            round_constants,
            q_absorb,
            q_full,
            q_pair,
            q_partial,
            q_squeeze,
            starts,
        }
    }
}

impl<F> Pow5Config<F> {
    /// The lane's advice columns.
    #[must_use]
    pub const fn lane(&self) -> Pow5Columns {
        self.lane
    }

    /// The round-constant columns.
    #[must_use]
    pub const fn round_constants(&self) -> RoundConstantColumns {
        self.round_constants
    }

    /// The states a hash may start from, in configuration order.
    pub fn initial_states(&self) -> impl Iterator<Item = &[F; WIDTH]> {
        self.starts.iter().map(|start| &start.state)
    }
}

/// One absorbed word: a copied cell or a constant.
#[derive(Clone, Copy, Debug)]
pub enum AbsorbInput<'w, F: PastaField> {
    /// A cell, copied into the auxiliary column.
    Word(&'w Word<F>),
    /// A constant, pinned through the constants column.
    Constant(F),
}

impl<F: PastaField> AbsorbInput<'_, F> {
    /// The value.
    fn value(&self) -> Value<F> {
        match self {
            Self::Word(word) => word.value(),
            Self::Constant(constant) => Value::known(*constant),
        }
    }
}

/// What the first row of a permutation absorbs.
#[derive(Clone, Copy, Debug)]
pub enum Absorb<'w, F: PastaField> {
    /// Nothing: a plain permutation of the entering state.
    Nothing,
    /// Two words, added to state words 1 and 2.
    Block([AbsorbInput<'w, F>; 2]),
}

/// The state at row 0 of a block, ready to be permuted.
///
/// It is consumed by [`Pow5Chip::permute`] or [`Pow5Chip::squeeze`], so a
/// state can enter only one permutation.
#[derive(Debug)]
pub struct Pow5State<F: PastaField> {
    block: usize,
    value: Value<[F; WIDTH]>,
}

impl<F: PastaField> Pow5State<F> {
    /// The block whose row 0 holds this state.
    #[must_use]
    pub const fn block(&self) -> usize {
        self.block
    }

    /// The state value (unknown during key generation).
    #[must_use]
    pub const fn value(&self) -> Value<[F; WIDTH]> {
        self.value
    }
}

/// The values of one permutation block.
#[derive(Clone, Debug)]
struct BlockTrace<F> {
    /// The state on rows 0..=37 (row 37 is the next block's row 0).
    state: Vec<[F; WIDTH]>,
    /// Pair S-box outputs, by pair row.
    mids: Vec<F>,
    /// Word 1 after the last round: the squeezed output.
    output: F,
}

/// The trace of one permutation of `input` plus the absorbed words.
fn block_trace<F: PastaField>(
    params: &PoseidonParams<F>,
    input: [F; WIDTH],
    absorbed: [F; 2],
) -> BlockTrace<F> {
    let mut states = Vec::with_capacity(ROWS_PER_PERMUTATION + 1);
    let mut mids = Vec::with_capacity(PAIR_ROWS);
    states.push(input);
    let mut state = [input[0], input[1] + absorbed[0], input[2] + absorbed[1]];
    for offset in 0..ROWS_PER_PERMUTATION {
        match RowRound::at(offset) {
            RowRound::Full(r) | RowRound::Partial(r) => state = round(params, state, r),
            RowRound::Pair(r) => {
                mids.push(pow5(state[0] + params.round_constants()[r][0]));
                state = round(params, round(params, state, r), r + 1);
            }
        }
        states.push(state);
    }
    BlockTrace {
        output: state[1],
        state: states,
        mids,
    }
}

/// A Pow5 lane: lays out permutations block by block.
#[derive(Clone, Debug)]
pub struct Pow5Chip<F: PoseidonField> {
    config: Pow5Config<F>,
    next_block: usize,
    start_row: usize,
    end_row: usize,
    constant_source: Option<crate::GlueChip<F>>,
}

impl<F: PoseidonField> Pow5Chip<F> {
    /// A lane whose first block starts at row 0.
    #[must_use]
    pub const fn new(config: Pow5Config<F>) -> Self {
        Self {
            config,
            next_block: 0,
            start_row: 0,
            end_row: usize::MAX,
            constant_source: None,
        }
    }

    /// Uses fixed coefficient gates in the caller's shared arithmetic lane
    /// for absorbed constants. That lane must own disjoint rows.
    ///
    /// # Errors
    /// The source is not a bounded shared coefficient-only lane containing
    /// this lane's copy port, or a permutation was already reserved.
    pub fn set_constant_source(&mut self, source: crate::GlueChip<F>) -> Result<(), Error> {
        if self.next_block != 0 || !source.coefficient_source_for(&[self.config.lane.aux]) {
            return Err(Error::Synthesis);
        }
        self.constant_source = Some(source);
        Ok(())
    }

    /// Restricts the lane to `[0,end_row)` before any block is reserved.
    ///
    /// # Errors
    /// The lane already contains a reserved block.
    pub fn bound_rows(&mut self, end_row: usize) -> Result<(), Error> {
        if self.next_block != 0 {
            return Err(Error::Synthesis);
        }
        self.end_row = end_row;
        Ok(())
    }

    /// Reserves a disjoint prefix before an otherwise empty lane.
    ///
    /// # Errors
    /// A block already exists or the start exceeds the fixed end bound.
    pub fn start_at(&mut self, start_row: usize) -> Result<(), Error> {
        if self.next_block != 0 || start_row > self.end_row {
            return Err(Error::Synthesis);
        }
        self.start_row = start_row;
        Ok(())
    }

    fn admit_block(&self, block: usize) -> Result<(), Error> {
        self.block_row(block)?
            .checked_add(ROWS_PER_PERMUTATION)
            .filter(|end| *end <= self.end_row)
            .ok_or(Error::BoundsFailure)?;
        Ok(())
    }

    /// The configuration.
    #[must_use]
    pub const fn config(&self) -> &Pow5Config<F> {
        &self.config
    }

    /// The first block not reserved yet.
    #[must_use]
    pub const fn next_block(&self) -> usize {
        self.next_block
    }

    /// The absolute next row, including a reserved prefix (`37` per block).
    #[must_use]
    pub const fn rows_used(&self) -> usize {
        self.start_row
            .saturating_add(self.next_block.saturating_mul(ROWS_PER_PERMUTATION))
    }

    /// Row 0 of `block`.
    pub(crate) fn block_row(&self, block: usize) -> Result<usize, Error> {
        block
            .checked_mul(ROWS_PER_PERMUTATION)
            .and_then(|offset| self.start_row.checked_add(offset))
            .ok_or(Error::BoundsFailure)
    }

    /// Reserves a new block and pins its row-0 state to `initial`, which
    /// must be one of the configured start states.
    ///
    /// # Errors
    ///
    /// [`Error::Synthesis`] when `initial` has no start gate, and [`Error`]
    /// from the layout.
    pub fn start(
        &mut self,
        region: &mut Region<'_, F>,
        initial: [F; WIDTH],
    ) -> Result<Pow5State<F>, Error> {
        let selector = self
            .config
            .starts
            .iter()
            .find(|start| start.state == initial)
            .map(|start| start.selector)
            .ok_or(Error::Synthesis)?;
        let block = self.next_block;
        self.admit_block(block)?;
        self.next_block = block.checked_add(1).ok_or(Error::BoundsFailure)?;
        let row = self.block_row(block)?;
        selector.enable(region, row)?;
        for (column, value) in self.config.lane.state.into_iter().zip(initial) {
            assign_word(region, column, row, Value::known(value))?;
        }
        Ok(Pow5State {
            block,
            value: Value::known(initial),
        })
    }

    /// Permutes `state` after absorbing `absorb`; the result is the state at
    /// row 0 of the next block, which is reserved for it.
    ///
    /// # Errors
    ///
    /// [`Error::Synthesis`] when `state` is not the lane's latest state, and
    /// [`Error`] from the layout.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "taking the state by value lets it enter only one permutation"
    )]
    pub fn permute(
        &mut self,
        region: &mut Region<'_, F>,
        state: Pow5State<F>,
        absorb: Absorb<'_, F>,
    ) -> Result<Pow5State<F>, Error> {
        let Pow5State { block, value } = state;
        let next = block.checked_add(1).ok_or(Error::BoundsFailure)?;
        self.admit_block(next)?;
        let trace = self.lay_out(region, block, value, absorb, false)?;
        self.next_block = next.checked_add(1).ok_or(Error::BoundsFailure)?;
        let next_row = self.block_row(next)?;
        let output = trace
            .as_ref()
            .map(|trace| trace.state[ROWS_PER_PERMUTATION]);
        for (index, column) in self.config.lane.state.into_iter().enumerate() {
            assign_word(region, column, next_row, output.map(|state| state[index]))?;
        }
        Ok(Pow5State {
            block: next,
            value: output,
        })
    }

    /// Permute and expose the resulting word 1 while retaining continuation.
    ///
    /// Ordinary lanes can enable both the full final-round gate and its
    /// squeeze projection on the same row. This binds the output without a
    /// new column or witness-selected gate, allowing a fixed maximum-length
    /// transcript to select its constrained final permutation output.
    ///
    /// # Errors
    /// Compact phase lanes cannot enable both final-round codes; they are
    /// rejected before assignment. Otherwise the errors of [`Self::permute`].
    pub fn permute_with_output(
        &mut self,
        region: &mut Region<'_, F>,
        state: Pow5State<F>,
        absorb: Absorb<'_, F>,
    ) -> Result<(Pow5State<F>, Word<F>), Error> {
        if !matches!(self.config.q_full, Enable::Selector(_))
            || !matches!(self.config.q_squeeze, Enable::Selector(_))
        {
            return Err(Error::Synthesis);
        }
        let row = self
            .block_row(state.block)?
            .checked_add(LAST_ROUND)
            .ok_or(Error::BoundsFailure)?;
        let next = self.permute(region, state, absorb)?;
        self.config.q_squeeze.enable(region, row)?;
        let output = assign_word(
            region,
            self.config.lane.aux,
            row,
            next.value.map(|state| state[1]),
        )?;
        Ok((next, output))
    }

    /// Permutes `state` after absorbing `absorb` and returns word 1 of the
    /// result (the sponge output), computed by the squeeze gate in place of
    /// the last round's next-row state.
    ///
    /// # Errors
    ///
    /// As [`Self::permute`].
    #[allow(
        clippy::needless_pass_by_value,
        reason = "taking the state by value lets it enter only one permutation"
    )]
    pub fn squeeze(
        &mut self,
        region: &mut Region<'_, F>,
        state: Pow5State<F>,
        absorb: Absorb<'_, F>,
    ) -> Result<Word<F>, Error> {
        let Pow5State { block, value } = state;
        let trace = self.lay_out(region, block, value, absorb, true)?;
        let row = self
            .block_row(block)?
            .checked_add(LAST_ROUND)
            .ok_or(Error::BoundsFailure)?;
        assign_word(
            region,
            self.config.lane.aux,
            row,
            trace.map(|trace| trace.output),
        )
    }

    /// Lays out rows 0..=36 of `block`, whose row 0 holds `entering`:
    /// constants, selectors, the absorbed words, the state on rows 1..=36
    /// and the pair S-box outputs.
    fn lay_out(
        &self,
        region: &mut Region<'_, F>,
        block: usize,
        entering: Value<[F; WIDTH]>,
        absorb: Absorb<'_, F>,
        squeeze: bool,
    ) -> Result<Value<BlockTrace<F>>, Error> {
        if block.checked_add(1) != Some(self.next_block) {
            return Err(Error::Synthesis);
        }
        let params = F::rp57();
        let base = self.block_row(block)?;
        let rows_end = base
            .checked_add(ROWS_PER_PERMUTATION)
            .ok_or(Error::BoundsFailure)?;
        let config = &self.config;
        let lane = config.lane;
        let absorbed = match absorb {
            Absorb::Nothing => Value::known([F::ZERO; 2]),
            Absorb::Block([first, second]) => {
                for (offset, input) in [first, second].into_iter().enumerate() {
                    let row = base + offset;
                    match input {
                        AbsorbInput::Word(word) => copy_word(region, word, lane.aux, row)?,
                        AbsorbInput::Constant(constant) => {
                            if let Some(mut source) = self.constant_source.clone() {
                                let word = source.constant(region, constant)?;
                                copy_word(region, &word, lane.aux, row)?
                            } else {
                                assign_constant(region, lane.aux, row, constant)?
                            }
                        }
                    };
                }
                first.value().zip(second.value()).map(|(a, b)| [a, b])
            }
        };
        let trace = entering
            .zip(absorbed)
            .map(|(input, absorbed)| block_trace(params, input, absorbed));
        for (offset, row) in (base..rows_end).enumerate() {
            let selector = match RowRound::at(offset) {
                RowRound::Full(_) if offset == 0 && matches!(absorb, Absorb::Block(_)) => {
                    config.q_absorb
                }
                RowRound::Full(_) if offset == LAST_ROUND && squeeze => config.q_squeeze,
                RowRound::Full(_) => config.q_full,
                RowRound::Pair(_) => config.q_pair,
                RowRound::Partial(_) => config.q_partial,
            };
            selector.enable(region, row)?;
            let (first, second) = match RowRound::at(offset) {
                RowRound::Full(r) | RowRound::Partial(r) => (r, None),
                RowRound::Pair(r) => (r, Some(r + 1)),
            };
            let constants = params.round_constants();
            for (column, value) in config.round_constants.a.into_iter().zip(constants[first]) {
                region.assign_fixed(column, row, value)?;
            }
            if let Some(second) = second {
                for (column, value) in config.round_constants.b.into_iter().zip(constants[second]) {
                    region.assign_fixed(column, row, value)?;
                }
                let pair = offset - HALF_FULL;
                let mid = trace.as_ref().map(|trace| trace.mids[pair]);
                assign_word(region, lane.aux, row, mid)?;
            }
            if offset > 0 {
                let entering = trace.as_ref().map(|trace| trace.state[offset]);
                for (index, column) in lane.state.into_iter().enumerate() {
                    assign_word(region, column, row, entering.map(|state| state[index]))?;
                }
            }
        }
        Ok(trace)
    }
}

/// Native reference: the RP57 permutation of `state` after absorbing
/// `absorbed` into words 1 and 2 ([`iroha_pasta::poseidon::permute`]).
#[must_use]
pub fn permute_native<F: PoseidonField>(state: [F; WIDTH], absorbed: [F; 2]) -> [F; WIDTH] {
    let mut state = [state[0], state[1] + absorbed[0], state[2] + absorbed[1]];
    iroha_pasta::poseidon::permute(&mut state);
    state
}

#[cfg(test)]
mod tests {
    use iroha_pasta::{Fp, Fq};

    use super::*;

    #[test]
    fn rows_cover_every_round_once() {
        let mut rounds = Vec::new();
        for offset in 0..ROWS_PER_PERMUTATION {
            match RowRound::at(offset) {
                RowRound::Full(r) => {
                    assert!(is_full_round(r));
                    rounds.push(r);
                }
                RowRound::Partial(r) => {
                    assert!(!is_full_round(r));
                    rounds.push(r);
                }
                RowRound::Pair(r) => {
                    assert!(!is_full_round(r) && !is_full_round(r + 1));
                    rounds.extend([r, r + 1]);
                }
            }
        }
        assert_eq!(rounds, (0..ROUNDS).collect::<Vec<_>>());
        assert_eq!(CELLS_PER_PERMUTATION, 148);
    }

    fn trace_matches_native<F: PoseidonField>() {
        let input = [F::from(3u64), F::from(5u64), -F::ONE];
        let absorbed = [F::from(11u64), F::from(13u64)];
        let trace = block_trace(F::rp57(), input, absorbed);
        let expected = permute_native(input, absorbed);
        assert_eq!(trace.state[ROWS_PER_PERMUTATION], expected);
        assert_eq!(trace.output, expected[1]);
        assert_eq!(trace.state.len(), ROWS_PER_PERMUTATION + 1);
        assert_eq!(trace.mids.len(), PAIR_ROWS);
        let mut plain = [F::ZERO; WIDTH];
        iroha_pasta::poseidon::permute(&mut plain);
        assert_eq!(permute_native([F::ZERO; WIDTH], [F::ZERO; 2]), plain);
        assert_eq!(pow5(F::from(2u64)), F::from(32u64));
    }

    #[derive(Clone)]
    struct Bounded<F: PoseidonField>(core::marker::PhantomData<F>);
    impl<F: PoseidonField> iroha_plonk::frontend::Circuit<F> for Bounded<F> {
        type Config = (Pow5Config<F>, Column<iroha_plonk::cs::Instance>);
        type FloorPlanner = iroha_plonk::frontend::SimpleFloorPlanner;
        type Params = ();
        fn without_witnesses(&self) -> Self {
            self.clone()
        }
        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let columns = Pow5Columns::allocate(meta);
            let constants = RoundConstantColumns::allocate(meta);
            let config = Pow5Config::configure(meta, columns, constants, &[[F::ZERO; WIDTH]]);
            let public = meta.instance_column(1);
            meta.enable_equality(public);
            (config, public)
        }
        fn synthesize(
            &self,
            (config, public): Self::Config,
            mut layouter: impl iroha_plonk::frontend::Layouter<F>,
        ) -> Result<(), Error> {
            let mut chip = Pow5Chip::new(config);
            let result = layouter.assign_region(
                || "bounded complete block",
                |mut region| {
                    chip.bound_rows(ROWS_PER_PERMUTATION - 1)?;
                    assert!(chip.start(&mut region, [F::ZERO; WIDTH]).is_err());
                    assert_eq!(chip.rows_used(), 0);
                    chip.bound_rows(ROWS_PER_PERMUTATION + 16)?;
                    chip.start_at(16)?;
                    assert_eq!(chip.rows_used(), 16);
                    let state = chip.start(&mut region, [F::ZERO; WIDTH])?;
                    assert!(chip.bound_rows(2 * ROWS_PER_PERMUTATION).is_err());
                    // A refused continuation must reserve/assign nothing. The
                    // private reconstructed state lets this test finish the exact
                    // existing block and check for partial writes after refusal.
                    let original = Pow5State {
                        block: state.block,
                        value: state.value,
                    };
                    assert!(chip.permute(&mut region, state, Absorb::Nothing).is_err());
                    assert_eq!(chip.rows_used(), ROWS_PER_PERMUTATION + 16);
                    assert!(chip.start_at(0).is_err());
                    chip.squeeze(&mut region, original, Absorb::Nothing)
                },
            )?;
            layouter.constrain_instance(result.cell(), public, 0)
        }
    }
    fn bounded_case<F: PoseidonField>() {
        let expected = permute_native([F::ZERO; WIDTH], [F::ZERO; 2])[1];
        let circuit = Bounded::<F>(core::marker::PhantomData);
        assert!(
            iroha_plonk::check::check_circuit(
                &circuit,
                7,
                &[vec![expected]],
                iroha_plonk::check::CheckMode::Strict
            )
            .unwrap()
            .is_satisfied()
        );
    }
    #[test]
    fn bounded_lane_refuses_before_assigning_or_reserving() {
        bounded_case::<Fp>();
        bounded_case::<Fq>();
    }

    #[test]
    fn block_trace_is_the_native_permutation() {
        trace_matches_native::<Fp>();
        trace_matches_native::<Fq>();
    }
}
