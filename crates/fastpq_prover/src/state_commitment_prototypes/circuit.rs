//! In-circuit witness verification of the tree candidates.
//!
//! One relation, written against [`crate::air::SemanticAir`], executes a
//! *program* of sponge permutations. Each permutation occupies one block of
//! rows; the last row of a block is its link row, where the next block's input
//! state is tied to the block's output, to verifier-known words and to a
//! sibling:
//!
//! - **fresh**: capacity and rate come from verifier-known words;
//! - **absorb**: verifier-known words are added to the rate;
//! - **compress**: the capacity is verifier-known, one half of the rate is the
//!   previous digest and the other half is a sibling that is private, a
//!   verifier-known digest or the digest kept in a register;
//! - **save** keeps a block's digest in one register of a small register file
//!   for a later compression, and **anchor** requires a block's digest to
//!   equal the public root.
//!
//! A witness of any tree candidate becomes such a program: the sponge over the
//! key and value bytes of the statement, the leaf compression, the path
//! compressions and the root normalisation with the schema digest. A
//! complete-range witness of a tree with sorted leaves is evaluated once, as
//! the tree it is: a hidden subtree is a private sibling, and a branch whose
//! two children are both computed keeps the first child's digest in a register
//! while the second is computed. The relation therefore constrains every hash
//! the native verifier computes exactly once, and binds the statement, the
//! schema digest and the root as verifier-known values. The number of
//! registers is the number the evaluation schedule of the statement uses; it
//! is fixed for one trace and is part of the relation's identity and width.
//!
//! Three things stay outside the relation and are stated with every
//! measurement:
//!
//! - the structural checks of a witness that involve no hash (key order
//!   against a disclosed neighbour, the shape rules of a range witness) run on
//!   verifier-known values when the program is derived, and the skeleton they
//!   read (disclosed keys, branching bit indices, directions that the
//!   statement fixes) is public. A relation that hides the key, as a State
//!   read inside a private execution proof needs, must make those words
//!   private and constrain them: [`super::key_gadgets`] holds the two gadgets
//!   that does take, built and checked as relations of their own, not composed
//!   into this trace;
//! - the linked-leaf map anchors the chain of every leaf of a range, so it
//!   normalises the root once per leaf where its native verifier compares
//!   structure roots and normalises once;
//! - the relation has only the uncommitted reference of
//!   [`crate::air::build_reference`]: no commitment, no masking, no FRI. A
//!   committed proof of it does not exist until task B.2.
//!
//! TODO(G.3): delete with the prototypes, or move the relation of the selected
//! construction to its owner and compose the key gadgets into its trace.
//! TODO(B.2): committed proofs of this relation.

use core::marker::PhantomData;
use std::{collections::BTreeMap, sync::Mutex};

use sha2::{Digest as _, Sha256};

use super::{
    DOMAIN_BRANCH, DOMAIN_KEY, DOMAIN_LEAF, DOMAIN_LINK, DOMAIN_PAGE_NODE, DOMAIN_ROOT,
    DOMAIN_VALUE, Reject,
    btree::MerkleBTree,
    critbit::PathStep,
    fringe::{LeafRole, OpenNode, Opened},
    hash::{
        AlgebraicSponge, DIGEST_BYTES, Digest, Permutation12, SPONGE_RATE, ZERO_DIGEST,
        bytes_capacity, compress_capacity, pack_bytes,
    },
    key_gadgets::GadgetUse,
    keyed::{PrototypeSchema, composite_key, composite_range, root_digest},
    linked::{Link, LinkedLeaf, LinkedLeafMap},
    poseidon2::{self, Poseidon2Goldilocks12},
    radix::RadixTree,
    rescue::{self, RescuePrime64},
    value_digest,
};
use crate::{
    Error, Result,
    air::{AirSchema, PolynomialField, SemanticAir, WorkLimits},
    field::add_base,
};

/// A width-12 permutation with a row-per-round relation.
pub trait AirPermutation: Permutation12 {
    /// Stable identity of the relation layout for this permutation, without
    /// the register count.
    const RELATION: &'static str;
    /// Trace rows of one permutation, a power of two; the last is the link row.
    const ROWS: usize;
    /// Verifier-known periodic columns: round selectors and round constants.
    const PERIODIC: usize;

    /// Value of periodic column `column` at row `row` of a block.
    fn periodic(row: usize, column: usize) -> u64;

    /// The state at every row of one permutation of `input`: `ROWS` states,
    /// the first being the input and the last the output.
    fn states(input: [u64; 12]) -> Vec<[u64; 12]>;

    /// The twelve round numerators of one row transition. They vanish on every
    /// row of an honest permutation and identically on a link row, where every
    /// round selector is zero.
    fn round_numerators<F: PolynomialField>(
        periodic: &[F],
        current: &[F; 12],
        next: &[F; 12],
    ) -> [F; 12];
}

impl AirPermutation for Poseidon2Goldilocks12 {
    const RELATION: &'static str =
        "iroha:g2:state-witness-chain:poseidon2-goldilocks-t12:row-per-round:register-file:v0";
    /// The input, the initial linear layer, thirty rounds: 32 states.
    const ROWS: usize = poseidon2::ROUNDS + 2;
    /// Linear, full and partial selectors, then twelve round constants.
    const PERIODIC: usize = 3 + poseidon2::WIDTH;

    fn periodic(row: usize, column: usize) -> u64 {
        // Row 0 applies the initial linear layer; row `r` in `1..=ROUNDS`
        // applies round `r - 1`; the last row is the link row.
        let round = row
            .checked_sub(1)
            .filter(|round| *round < poseidon2::ROUNDS);
        match (column, round) {
            (0, _) => u64::from(row == 0),
            (1, Some(round)) => u64::from(poseidon2::is_full_round(round)),
            (2, Some(round)) => u64::from(!poseidon2::is_full_round(round)),
            (3.., Some(round)) => poseidon2::round_constants(round)[column - 3],
            _ => 0,
        }
    }

    fn states(input: [u64; 12]) -> Vec<[u64; 12]> {
        poseidon2::permutation_states(input)
    }

    fn round_numerators<F: PolynomialField>(
        periodic: &[F],
        current: &[F; 12],
        next: &[F; 12],
    ) -> [F; 12] {
        let (linear, full, partial) = (periodic[0], periodic[1], periodic[2]);
        let constants: [F; 12] = core::array::from_fn(|index| periodic[3 + index]);
        let after_linear = poseidon2::external_layer(current);
        let after_full = poseidon2::full_round(current, &constants);
        let after_partial = poseidon2::partial_round(current, constants[0]);
        core::array::from_fn(|index| {
            linear
                .mul(next[index].sub(after_linear[index]))
                .add(full.mul(next[index].sub(after_full[index])))
                .add(partial.mul(next[index].sub(after_partial[index])))
        })
    }
}

impl AirPermutation for RescuePrime64 {
    const RELATION: &'static str =
        "iroha:g2:state-witness-chain:rescue-prime-rp64-256:row-per-round:register-file:v0";
    /// The input and seven rounds: 8 states.
    const ROWS: usize = rescue::ROUNDS + 1;
    /// The round selector, then both sets of twelve round constants.
    const PERIODIC: usize = 1 + 2 * rescue::WIDTH;

    fn periodic(row: usize, column: usize) -> u64 {
        if row >= rescue::ROUNDS {
            return 0;
        }
        match column {
            0 => 1,
            1..=12 => rescue::first_constants(row)[column - 1],
            _ => rescue::second_constants(row)[column - 13],
        }
    }

    fn states(input: [u64; 12]) -> Vec<[u64; 12]> {
        rescue::permutation_states(input)
    }

    fn round_numerators<F: PolynomialField>(
        periodic: &[F],
        current: &[F; 12],
        next: &[F; 12],
    ) -> [F; 12] {
        let round = periodic[0];
        let first: [F; 12] = core::array::from_fn(|index| periodic[1 + index]);
        // `(MDS^-1(next - ARK2))^7 = MDS(current^7) + ARK1`: the inverse S-box
        // of the second half is checked forwards, without auxiliary columns.
        let middle = rescue::first_half(current, &first);
        let lifted: [F; 12] = core::array::from_fn(|index| next[index].sub(periodic[13 + index]));
        let unmixed = rescue::inverse_mds_layer(&lifted);
        core::array::from_fn(|index| round.mul(rescue::sbox(unmixed[index]).sub(middle[index])))
    }
}

/// The sibling of a compression.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sibling {
    /// A digest only the prover knows.
    Private(Digest),
    /// A digest the verifier computes from the statement.
    Public(Digest),
    /// The digest kept in this register by the last block that saved to it.
    Saved(usize),
}

/// How a block's input state is formed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Input {
    /// A new state from verifier-known capacity and rate words.
    Fresh {
        /// Capacity words.
        capacity: [u64; 4],
        /// Rate words.
        message: [u64; SPONGE_RATE],
    },
    /// The previous output state with verifier-known words added to its rate.
    Absorb {
        /// Words added to the rate.
        message: [u64; SPONGE_RATE],
    },
    /// The previous digest compressed with a sibling.
    Compress {
        /// Capacity words.
        capacity: [u64; 4],
        /// Whether the previous digest is the right input.
        previous_right: bool,
        /// The other input.
        sibling: Sibling,
        /// Whether the side is fixed by the statement (a verifier-known value)
        /// rather than chosen by the prover.
        side_public: bool,
    },
}

/// One permutation of a program.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Block {
    /// How the input state is formed.
    pub input: Input,
    /// Keep this block's digest in this register for a later
    /// [`Sibling::Saved`]. It replaces what the register held.
    pub save: Option<usize>,
    /// Require this block's digest to equal the program's root.
    pub anchor: bool,
}

impl Block {
    const fn new(input: Input) -> Self {
        Self {
            input,
            save: None,
            anchor: false,
        }
    }
}

/// A witness verification as a sequence of permutations anchored to one root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Program {
    /// The permutations in execution order. The first is always fresh.
    pub blocks: Vec<Block>,
    /// The normalised root every anchored digest must equal.
    pub root: Digest,
}

impl Program {
    /// The program with every private sibling erased: what a verifier holds.
    #[must_use]
    pub fn public_view(&self) -> Self {
        let mut view = self.clone();
        for block in &mut view.blocks {
            if let Input::Compress {
                sibling: Sibling::Private(digest),
                ..
            } = &mut block.input
            {
                *digest = ZERO_DIGEST;
            }
        }
        view
    }

    /// Number of permutations the statement needs, before padding.
    #[must_use]
    pub fn permutations(&self) -> usize {
        self.blocks.len()
    }

    /// Registers the program's schedule uses: one more than the highest
    /// register a block saves to or reads, and at least one.
    #[must_use]
    pub fn registers(&self) -> usize {
        self.blocks
            .iter()
            .flat_map(|block| {
                let read = match block.input {
                    Input::Compress {
                        sibling: Sibling::Saved(register),
                        ..
                    } => Some(register),
                    _ => None,
                };
                [block.save, read]
            })
            .flatten()
            .max()
            .map_or(1, |highest| highest + 1)
    }

    /// Compressions whose sibling only the prover knows.
    #[must_use]
    pub fn private_siblings(&self) -> usize {
        self.blocks
            .iter()
            .filter(|block| {
                matches!(
                    block.input,
                    Input::Compress {
                        sibling: Sibling::Private(_),
                        ..
                    }
                )
            })
            .count()
    }
}

/// Private columns: the state, the side bit, then four words per register.
const STATE: usize = 0;
const SIDE: usize = 12;
const SAVED: usize = 13;
/// Verifier-known columns in front of the register selectors, as offsets from
/// the first verifier-known column.
const LINK: usize = 0;
const FRESH: usize = 1;
const ABSORB: usize = 2;
const COMPRESS: usize = 3;
const ANCHOR: usize = 4;
const SIBLING_PUBLIC: usize = 5;
const SIDE_PUBLIC: usize = 6;
const SIDE_VALUE: usize = 7;
const CAPACITY: usize = 8;
const MESSAGE: usize = 12;
const FIXED_PUBLIC: usize = 20;
/// A selector times a seventh power of a state column.
const DEGREE: usize = 8;

/// Column and numerator layout for one register count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Layout {
    registers: usize,
}

impl Layout {
    /// Private columns: also the index of the first verifier-known column.
    const fn private(self) -> usize {
        SAVED + 4 * self.registers
    }

    /// Word `word` of the digest kept in `register`.
    const fn saved(register: usize, word: usize) -> usize {
        SAVED + 4 * register + word
    }

    /// A verifier-known column in front of the register selectors.
    const fn fixed(self, offset: usize) -> usize {
        self.private() + offset
    }

    /// Selector of a link row that saves to `register`.
    const fn save(self, register: usize) -> usize {
        self.private() + FIXED_PUBLIC + register
    }

    /// Selector of a link row whose compression reads `register`.
    const fn load(self, register: usize) -> usize {
        self.private() + FIXED_PUBLIC + self.registers + register
    }

    /// First periodic column of the permutation.
    const fn periodic(self) -> usize {
        self.private() + FIXED_PUBLIC + 2 * self.registers
    }

    /// State transition, register, side bit, public side and anchor numerators.
    const fn constraints(self) -> usize {
        12 + 4 * self.registers + 1 + 1 + 4
    }
}

/// Constraint groups a test can switch off to show that each is load-bearing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConstraintGroup {
    /// The round numerators of the permutation.
    Rounds,
    /// The link-row numerators that tie a block's input to the previous output
    /// and to verifier-known words. Switching them off also drops the sibling
    /// bindings, which are terms of the same numerators.
    Link,
    /// The term that binds a sibling to a verifier-known digest.
    PublicSibling,
    /// The term that binds a sibling to the digest a register holds.
    SavedSibling,
    /// The numerators that make a register hold what was saved to it.
    Saved,
    /// The numerator that makes the side a bit.
    SideBoolean,
    /// The numerator that fixes a side the statement determines.
    PublicSide,
    /// The numerators that anchor a digest to the root.
    Anchor,
}

/// The identity of the relation of one permutation with one register count.
///
/// The count changes the column order, so it is part of the identity. The
/// strings are kept for the life of the process: a relation identity is a
/// static name, and a process sees only as many as it uses register counts.
fn relation_identity<P: AirPermutation>(registers: usize) -> &'static str {
    static NAMES: Mutex<BTreeMap<(&'static str, usize), &'static str>> =
        Mutex::new(BTreeMap::new());
    let mut names = NAMES
        .lock()
        .expect("the relation identity table is not poisoned");
    names.entry((P::RELATION, registers)).or_insert_with(|| {
        Box::leak(format!("{}:registers-{registers}", P::RELATION).into_boxed_str())
    })
}

/// The hash-chain relation of one program.
pub struct ChainAir<P> {
    rows: usize,
    blocks: usize,
    layout: Layout,
    identity: &'static str,
    public: Vec<Vec<u64>>,
    public_columns: Vec<usize>,
    root: Digest,
    statement: Vec<u8>,
    disabled: Option<ConstraintGroup>,
    permutation: PhantomData<P>,
}

/// Blocks after padding with idle permutations to a power of two.
fn padded_blocks(program: &Program) -> usize {
    program.blocks.len().max(1).next_power_of_two()
}

const IDLE: Block = Block::new(Input::Fresh {
    capacity: [0; 4],
    message: [0; SPONGE_RATE],
});

fn digest_of(state: &[u64; 12]) -> Digest {
    core::array::from_fn(|index| state[4 + index])
}

impl<P: AirPermutation> ChainAir<P> {
    /// Complete column count for a register count: private, link, register
    /// selector and periodic columns.
    #[must_use]
    pub const fn width_with(registers: usize) -> usize {
        Layout { registers }.periodic() + P::PERIODIC
    }

    /// Numerators for a register count.
    #[must_use]
    pub const fn constraints_with(registers: usize) -> usize {
        Layout { registers }.constraints()
    }

    /// Trace rows a program occupies after padding.
    #[must_use]
    pub fn rows_for(program: &Program) -> usize {
        padded_blocks(program) * P::ROWS
    }

    /// The relation a verifier builds from the public part of a program.
    ///
    /// # Panics
    /// Panics when the first block is not fresh: the trace is cyclic, so the
    /// first block cannot depend on the last one.
    #[must_use]
    pub fn new(program: &Program) -> Self {
        assert!(
            matches!(
                program.blocks.first().map(|block| block.input),
                None | Some(Input::Fresh { .. })
            ),
            "a program starts with a fresh block"
        );
        let layout = Layout {
            registers: program.registers(),
        };
        let blocks = padded_blocks(program);
        let rows = blocks * P::ROWS;
        let width = layout.periodic() + P::PERIODIC;
        let first = layout.private();
        let mut public = vec![vec![0_u64; rows]; width - first];
        let block_at = |index: usize| program.blocks.get(index).copied().unwrap_or(IDLE);
        for block in 0..blocks {
            for row in 0..P::ROWS {
                for column in 0..P::PERIODIC {
                    public[layout.periodic() - first + column][block * P::ROWS + row] =
                        P::periodic(row, column);
                }
            }
            // The link row describes this block's output and the next block's input.
            let row = (block + 1) * P::ROWS - 1;
            let mut set = |column: usize, value: u64| public[column - first][row] = value;
            let own = block_at(block);
            set(layout.fixed(LINK), 1);
            if let Some(register) = own.save {
                set(layout.save(register), 1);
            }
            set(layout.fixed(ANCHOR), u64::from(own.anchor));
            match block_at((block + 1) % blocks).input {
                Input::Fresh { capacity, message } => {
                    set(layout.fixed(FRESH), 1);
                    for (index, word) in capacity.iter().enumerate() {
                        set(layout.fixed(CAPACITY + index), *word);
                    }
                    for (index, word) in message.iter().enumerate() {
                        set(layout.fixed(MESSAGE + index), *word);
                    }
                }
                Input::Absorb { message } => {
                    set(layout.fixed(ABSORB), 1);
                    for (index, word) in message.iter().enumerate() {
                        set(layout.fixed(MESSAGE + index), *word);
                    }
                }
                Input::Compress {
                    capacity,
                    previous_right,
                    sibling,
                    side_public,
                } => {
                    set(layout.fixed(COMPRESS), 1);
                    for (index, word) in capacity.iter().enumerate() {
                        set(layout.fixed(CAPACITY + index), *word);
                    }
                    set(layout.fixed(SIDE_PUBLIC), u64::from(side_public));
                    set(
                        layout.fixed(SIDE_VALUE),
                        u64::from(side_public && previous_right),
                    );
                    match sibling {
                        Sibling::Private(_) => {}
                        Sibling::Public(digest) => {
                            set(layout.fixed(SIBLING_PUBLIC), 1);
                            for (index, word) in digest.iter().enumerate() {
                                set(layout.fixed(MESSAGE + index), *word);
                            }
                        }
                        Sibling::Saved(register) => set(layout.load(register), 1),
                    }
                }
            }
        }
        let identity = relation_identity::<P>(layout.registers);
        let mut hasher = Sha256::new();
        hasher.update(identity.as_bytes());
        hasher.update((rows as u64).to_le_bytes());
        for word in program.root {
            hasher.update(word.to_le_bytes());
        }
        for column in &public {
            for word in column {
                hasher.update(word.to_le_bytes());
            }
        }
        Self {
            rows,
            blocks,
            layout,
            identity,
            public,
            public_columns: (first..width).collect(),
            root: program.root,
            statement: hasher.finalize().to_vec(),
            disabled: None,
            permutation: PhantomData,
        }
    }

    /// The same relation without one constraint group. For mutation tests.
    #[cfg(test)]
    fn without(mut self, group: ConstraintGroup) -> Self {
        self.disabled = Some(group);
        self
    }

    /// Permutation blocks of the trace, padding included.
    #[must_use]
    pub const fn blocks(&self) -> usize {
        self.blocks
    }

    /// Registers of the relation's register file.
    #[must_use]
    pub const fn registers(&self) -> usize {
        self.layout.registers
    }

    /// Complete column count of this relation.
    #[must_use]
    pub const fn width(&self) -> usize {
        Self::width_with(self.layout.registers)
    }

    /// The prover's column-major trace of a program.
    ///
    /// The verifier-known columns are copied from the relation; the state, the
    /// side bits and the registers are computed by executing the program. A
    /// program whose anchored digest is not the root still yields a trace; the
    /// relation rejects it.
    ///
    /// # Panics
    /// Panics when the program uses a register the relation does not have.
    #[must_use]
    pub fn witness_columns(&self, program: &Program) -> Vec<Vec<u64>> {
        assert!(
            program.registers() <= self.layout.registers,
            "the program uses a register the relation does not have"
        );
        let first = self.layout.private();
        let mut columns = vec![vec![0_u64; self.rows]; self.width()];
        for (ordinal, column) in self.public.iter().enumerate() {
            columns[first + ordinal].copy_from_slice(column);
        }
        let block_at = |index: usize| program.blocks.get(index).copied().unwrap_or(IDLE);
        // The registers are cyclic: they enter the first block holding what
        // the saves of the previous cycle left.
        let mut saved = vec![ZERO_DIGEST; self.layout.registers];
        let mut last_output = [0_u64; 12];
        for pass in 0..2 {
            let mut output = [0_u64; 12];
            for block in 0..self.blocks {
                let own = block_at(block);
                let input = match own.input {
                    Input::Fresh { capacity, message } => {
                        let mut state = [0_u64; 12];
                        state[..4].copy_from_slice(&capacity);
                        state[4..].copy_from_slice(&message);
                        state
                    }
                    Input::Absorb { message } => {
                        let mut state = output;
                        for (cell, word) in state[4..].iter_mut().zip(message) {
                            *cell = add_base(*cell, word);
                        }
                        state
                    }
                    Input::Compress {
                        capacity,
                        previous_right,
                        sibling,
                        ..
                    } => {
                        let other = match sibling {
                            Sibling::Private(digest) | Sibling::Public(digest) => digest,
                            Sibling::Saved(register) => saved[register],
                        };
                        let previous = digest_of(&output);
                        let (left, right) = if previous_right {
                            (other, previous)
                        } else {
                            (previous, other)
                        };
                        let mut state = [0_u64; 12];
                        state[..4].copy_from_slice(&capacity);
                        state[4..8].copy_from_slice(&left);
                        state[8..].copy_from_slice(&right);
                        state
                    }
                };
                // The save of the previous block takes effect after this
                // block's input was formed from what the registers held.
                let previous_block = if block == 0 {
                    (pass == 1).then(|| (block_at(self.blocks - 1), last_output))
                } else {
                    Some((block_at(block - 1), output))
                };
                if let Some((before, digest)) = previous_block
                    && let Some(register) = before.save
                {
                    saved[register] = digest_of(&digest);
                }
                let states = P::states(input);
                output = states[P::ROWS - 1];
                if pass == 1 {
                    for (row, state) in states.iter().enumerate() {
                        let index = block * P::ROWS + row;
                        for (column, word) in state.iter().enumerate() {
                            columns[STATE + column][index] = *word;
                        }
                        for (register, digest) in saved.iter().enumerate() {
                            for (word, value) in digest.iter().enumerate() {
                                columns[Layout::saved(register, word)][index] = *value;
                            }
                        }
                    }
                    if let Input::Compress { previous_right, .. } =
                        block_at((block + 1) % self.blocks).input
                    {
                        columns[SIDE][(block + 1) * P::ROWS - 1] = u64::from(previous_right);
                    }
                }
            }
            last_output = output;
        }
        columns
    }

    /// Caller ceilings for the uncommitted reference of this relation: the
    /// supported trace order and the relation's own cell and constraint counts,
    /// with no ceiling on the reference's declared payload and work.
    #[must_use]
    pub fn reference_limits(&self) -> WorkLimits {
        WorkLimits {
            max_trace_rows: crate::air::MAX_REFERENCE_TRACE_ROWS,
            max_trace_cells: self.rows * self.width(),
            max_constraints: self.layout.constraints(),
            max_statement_bytes: self.statement.len(),
            max_payload_bytes: usize::MAX,
            max_work_units: usize::MAX,
        }
    }

    fn enabled(&self, group: ConstraintGroup) -> bool {
        self.disabled != Some(group)
    }
}

impl<P: AirPermutation + Sync> SemanticAir for ChainAir<P> {
    fn schema(&self) -> AirSchema {
        AirSchema {
            identity: self.identity,
            trace_rows: self.rows,
            width: self.width(),
            constraints: self.layout.constraints(),
            // Every column polynomial has degree below the row count.
            numerator_degree_bound: DEGREE * (self.rows - 1) + 1,
        }
    }

    fn statement_bytes(&self) -> &[u8] {
        &self.statement
    }

    fn public_columns(&self) -> &[usize] {
        &self.public_columns
    }

    fn public_value(&self, ordinal: usize, row: usize) -> Result<u64> {
        self.public
            .get(ordinal)
            .and_then(|column| column.get(row))
            .copied()
            .ok_or(Error::QueryIndexOutOfRange {
                index: row,
                len: self.rows,
            })
    }

    fn evaluate<F: PolynomialField>(&self, _point: F, current: &[F], next: &[F]) -> Result<Vec<F>> {
        let layout = self.layout;
        let width = self.width();
        if current.len() != width || next.len() != width {
            return Err(Error::QueryIndexOutOfRange {
                index: current.len().max(next.len()),
                len: width,
            });
        }
        let fixed = |offset: usize| current[layout.fixed(offset)];
        let state: [F; 12] = core::array::from_fn(|index| current[STATE + index]);
        let after: [F; 12] = core::array::from_fn(|index| next[STATE + index]);
        let rounds = if self.enabled(ConstraintGroup::Rounds) {
            P::round_numerators(&current[layout.periodic()..], &state, &after)
        } else {
            [F::ZERO; 12]
        };
        let link = fixed(LINK);
        let side = current[SIDE];
        let other_side = F::ONE.sub(side);
        let mut numerators = Vec::with_capacity(layout.constraints());
        for index in 0..12 {
            let capacity = index < 4;
            let word = index % 4;
            let fresh = after[index].sub(if capacity {
                fixed(CAPACITY + index)
            } else {
                fixed(MESSAGE + index - 4)
            });
            let absorb = if capacity {
                after[index].sub(state[index])
            } else {
                after[index]
                    .sub(state[index])
                    .sub(fixed(MESSAGE + index - 4))
            };
            let compress = if capacity {
                after[index].sub(fixed(CAPACITY + index))
            } else {
                // The half that holds the previous digest equals it; the
                // other half equals a bound sibling, or is free.
                let previous = after[index].sub(state[4 + word]);
                let mut sibling = F::ZERO;
                if self.enabled(ConstraintGroup::PublicSibling) {
                    sibling = sibling
                        .add(fixed(SIBLING_PUBLIC).mul(after[index].sub(fixed(MESSAGE + word))));
                }
                if self.enabled(ConstraintGroup::SavedSibling) {
                    for register in 0..layout.registers {
                        sibling = sibling.add(
                            current[layout.load(register)]
                                .mul(after[index].sub(current[Layout::saved(register, word)])),
                        );
                    }
                }
                if index < 8 {
                    other_side.mul(previous).add(side.mul(sibling))
                } else {
                    side.mul(previous).add(other_side.mul(sibling))
                }
            };
            let linked = if self.enabled(ConstraintGroup::Link) {
                fixed(FRESH)
                    .mul(fresh)
                    .add(fixed(ABSORB).mul(absorb))
                    .add(fixed(COMPRESS).mul(compress))
            } else {
                F::ZERO
            };
            numerators.push(rounds[index].add(link.mul(linked)));
        }
        for register in 0..layout.registers {
            for word in 0..4 {
                // A register changes only where a link row saves to it.
                let column = Layout::saved(register, word);
                let kept = next[column].sub(current[column]);
                let taken = link
                    .mul(current[layout.save(register)])
                    .mul(state[4 + word].sub(current[column]));
                numerators.push(if self.enabled(ConstraintGroup::Saved) {
                    kept.sub(taken)
                } else {
                    F::ZERO
                });
            }
        }
        numerators.push(if self.enabled(ConstraintGroup::SideBoolean) {
            side.mul(side.sub(F::ONE))
        } else {
            F::ZERO
        });
        numerators.push(if self.enabled(ConstraintGroup::PublicSide) {
            link.mul(fixed(SIDE_PUBLIC))
                .mul(side.sub(fixed(SIDE_VALUE)))
        } else {
            F::ZERO
        });
        for word in 0..4 {
            numerators.push(if self.enabled(ConstraintGroup::Anchor) {
                link.mul(fixed(ANCHOR))
                    .mul(state[4 + word].sub(F::embed_base(self.root[word])))
            } else {
                F::ZERO
            });
        }
        Ok(numerators)
    }
}

/// Blocks of the sponge over a byte string: `AlgebraicSponge::hash_bytes`.
fn sponge_blocks(domain: u64, bytes: &[u8]) -> Vec<Block> {
    pack_bytes(bytes)
        .into_iter()
        .enumerate()
        .map(|(index, message)| {
            Block::new(if index == 0 {
                Input::Fresh {
                    capacity: bytes_capacity(domain),
                    message,
                }
            } else {
                Input::Absorb { message }
            })
        })
        .collect()
}

fn compress(
    domain: u64,
    aux: u64,
    previous_right: bool,
    sibling: Sibling,
    side_public: bool,
) -> Block {
    Block::new(Input::Compress {
        capacity: compress_capacity(domain, aux),
        previous_right,
        sibling,
        side_public,
    })
}

/// A compression of two verifier-known digests.
fn public_compress(domain: u64, aux: u64, left: &Digest, right: &Digest) -> Block {
    let mut message = [0_u64; SPONGE_RATE];
    message[..4].copy_from_slice(left);
    message[4..].copy_from_slice(right);
    Block::new(Input::Fresh {
        capacity: compress_capacity(domain, aux),
        message,
    })
}

/// Builder of the chains of one statement.
struct Chains {
    blocks: Vec<Block>,
    schema: Digest,
    root: Digest,
}

impl Chains {
    fn new(schema: Digest, root: Digest) -> Self {
        Self {
            blocks: Vec::new(),
            schema,
            root,
        }
    }

    /// The block written last.
    fn last(&mut self) -> &mut Block {
        self.blocks
            .last_mut()
            .expect("a chain has a block before it is extended")
    }

    /// The sponge over a byte string; its digest is the running digest.
    fn sponge(&mut self, domain: u64, bytes: &[u8]) {
        self.blocks.extend(sponge_blocks(domain, bytes));
    }

    /// An entry leaf from key and value bytes. The key digest waits in
    /// `register` while the value is hashed.
    fn entry(&mut self, key: &[u8], value: &[u8], register: usize) {
        self.sponge(DOMAIN_KEY, key);
        self.last().save = Some(register);
        self.sponge(DOMAIN_VALUE, value);
        self.blocks.push(compress(
            DOMAIN_LEAF,
            0,
            true,
            Sibling::Saved(register),
            true,
        ));
    }

    /// An entry leaf from key bytes and a disclosed value digest.
    fn disclosed(&mut self, key: &[u8], value: &Digest) {
        self.sponge(DOMAIN_KEY, key);
        self.blocks.push(compress(
            DOMAIN_LEAF,
            0,
            false,
            Sibling::Public(*value),
            true,
        ));
    }

    /// The compressions of a bottom-up path under one branch domain.
    fn path(&mut self, domain: u64, path: &[PathStep], side_public: bool) {
        for step in path {
            self.blocks.push(compress(
                domain,
                u64::from(step.crit),
                step.right,
                Sibling::Private(step.sibling),
                side_public,
            ));
        }
    }

    /// The root normalisation with the schema digest, anchored to the root.
    fn anchor(&mut self) {
        let mut block = compress(DOMAIN_ROOT, 0, false, Sibling::Public(self.schema), true);
        block.anchor = true;
        self.blocks.push(block);
    }

    /// The normalisation of a verifier-known structure root.
    fn anchor_public(&mut self, structure: &Digest) {
        let mut block = public_compress(DOMAIN_ROOT, 0, structure, &self.schema);
        block.anchor = true;
        self.blocks.push(block);
    }

    fn finish(self) -> Program {
        Program {
            blocks: self.blocks,
            root: self.root,
        }
    }
}

/// Registers the evaluation of every node of an opened tree uses, `None` for
/// a hidden subtree, which is a sibling and is never evaluated.
///
/// A claimed leaf keeps its key digest in one register while its value is
/// hashed; a disclosed leaf needs none. A branch over two computed children
/// evaluates the child that needs more registers first and keeps its digest
/// in one register while the other child is evaluated.
fn register_needs(opened: &Opened) -> Vec<Option<usize>> {
    let mut needs: Vec<Option<usize>> = Vec::with_capacity(opened.nodes.len());
    for (kind, _) in &opened.nodes {
        let need = match *kind {
            OpenNode::Hidden => None,
            OpenNode::Leaf(leaf) => Some(usize::from(matches!(
                opened.leaves[leaf].role,
                LeafRole::Claimed(_)
            ))),
            OpenNode::Branch { left, right, .. } => match (needs[left], needs[right]) {
                (Some(left), Some(right)) => Some(if left == right {
                    left + 1
                } else {
                    left.max(right)
                }),
                (need, None) | (None, need) => need,
            },
        };
        needs.push(need);
    }
    needs
}

/// The blocks that evaluate one computed node of an opened tree, using the
/// registers from `base` on. The node's digest is the running digest.
fn fringe_node(
    chains: &mut Chains,
    domain: u64,
    opened: &Opened,
    entries: &[(&[u8], &[u8])],
    needs: &[Option<usize>],
    node: usize,
    base: usize,
) {
    match opened.nodes[node].0 {
        OpenNode::Hidden => unreachable!("a hidden subtree is a sibling and is never evaluated"),
        OpenNode::Leaf(leaf) => {
            let leaf = &opened.leaves[leaf];
            match leaf.role {
                LeafRole::Claimed(index) => chains.entry(&leaf.key, entries[index].1, base),
                LeafRole::Predecessor | LeafRole::Successor => {
                    chains.disclosed(&leaf.key, &leaf.value_digest);
                }
            }
        }
        OpenNode::Branch { aux, left, right } => {
            let aux = u64::from(aux);
            // Adjacency of the revealed leaves is read from the sides, so the
            // statement fixes every one of them.
            match (needs[left], needs[right]) {
                (Some(left_need), Some(right_need)) => {
                    let first_is_left = left_need >= right_need;
                    let (first, second) = if first_is_left {
                        (left, right)
                    } else {
                        (right, left)
                    };
                    fringe_node(chains, domain, opened, entries, needs, first, base);
                    chains.last().save = Some(base);
                    fringe_node(chains, domain, opened, entries, needs, second, base + 1);
                    // The running digest is the second child's.
                    chains.blocks.push(compress(
                        domain,
                        aux,
                        first_is_left,
                        Sibling::Saved(base),
                        true,
                    ));
                }
                (Some(_), None) => {
                    fringe_node(chains, domain, opened, entries, needs, left, base);
                    chains.blocks.push(compress(
                        domain,
                        aux,
                        false,
                        Sibling::Private(opened.nodes[right].1),
                        true,
                    ));
                }
                (None, Some(_)) => {
                    fringe_node(chains, domain, opened, entries, needs, right, base);
                    chains.blocks.push(compress(
                        domain,
                        aux,
                        true,
                        Sibling::Private(opened.nodes[left].1),
                        true,
                    ));
                }
                (None, None) => {
                    unreachable!("the opener refuses a branch over two hidden subtrees")
                }
            }
        }
    }
}

/// The program of an opened range witness of a binary tree with sorted
/// leaves: the tree is evaluated once, bottom-up, and its root is anchored.
fn fringe_program(
    chains: &mut Chains,
    domain: u64,
    opened: &Opened,
    entries: &[(&[u8], &[u8])],
) -> core::result::Result<(), Reject> {
    let Some(top) = opened.nodes.len().checked_sub(1) else {
        chains.anchor_public(&opened.root);
        return Ok(());
    };
    let needs = register_needs(opened);
    // An opened witness of a nonempty tree reveals a leaf.
    if needs[top].is_none() {
        return Err(Reject::NotProven);
    }
    fringe_node(chains, domain, opened, entries, &needs, top, 0);
    chains.anchor();
    Ok(())
}

/// The three witness kinds of a tree candidate as programs.
///
/// Keys are composite keys and `schema` and `root` are digests; see
/// [`inclusion_statement`], [`absence_statement`] and [`range_statement`] for
/// the table-level forms.
pub trait WitnessPrograms: super::Engine {
    /// Gadget instances an absence statement over a private key needs beside
    /// the hash chain: the structural checks this relation leaves to
    /// verifier-known values.
    const ABSENCE_GADGETS: GadgetUse;
    /// Gadget instances a complete-range statement over private bounds needs.
    const RANGE_GADGETS: GadgetUse;

    /// Program of an inclusion witness.
    ///
    /// # Errors
    /// The witness is not a canonical inclusion witness.
    fn inclusion_program(
        schema: Digest,
        root: Digest,
        key: &[u8],
        value: &[u8],
        witness: &[u8],
    ) -> core::result::Result<Program, Reject>;

    /// Program of an absence witness.
    ///
    /// # Errors
    /// The witness is not a canonical absence witness of `key`.
    fn absence_program(
        schema: Digest,
        root: Digest,
        key: &[u8],
        witness: &[u8],
    ) -> core::result::Result<Program, Reject>;

    /// Program of a complete-range witness.
    ///
    /// # Errors
    /// The witness is not a canonical range witness of the statement.
    fn range_program(
        schema: Digest,
        root: Digest,
        lower: &[u8],
        upper: Option<&[u8]>,
        entries: &[(&[u8], &[u8])],
        witness: &[u8],
    ) -> core::result::Result<Program, Reject>;
}

/// Programs of the radix tree over a sponge profile. The sides of an absence
/// path are bits of the absent key at the disclosed branching indices, so the
/// statement fixes them; a disclosed leaf that is not on that search path does
/// not reach the root.
impl<P: AirPermutation> WitnessPrograms for RadixTree<AlgebraicSponge<P>> {
    /// The bits of the absent key at the branching indices and at one index
    /// where the disclosed leaf's key differs, and that bit of the leaf's key.
    const ABSENCE_GADGETS: GadgetUse = GadgetUse {
        bit_scans: 2,
        comparisons: 0,
    };
    /// The predecessor below the lower bound and the successor at or above
    /// the upper bound.
    const RANGE_GADGETS: GadgetUse = GadgetUse {
        bit_scans: 0,
        comparisons: 2,
    };

    fn inclusion_program(
        schema: Digest,
        root: Digest,
        key: &[u8],
        value: &[u8],
        witness: &[u8],
    ) -> core::result::Result<Program, Reject> {
        let path = Self::open_inclusion(key, witness)?;
        let mut chains = Chains::new(schema, root);
        chains.entry(key, value, 0);
        chains.path(DOMAIN_BRANCH, &path, false);
        chains.anchor();
        Ok(chains.finish())
    }

    fn absence_program(
        schema: Digest,
        root: Digest,
        key: &[u8],
        witness: &[u8],
    ) -> core::result::Result<Program, Reject> {
        let mut chains = Chains::new(schema, root);
        match Self::open_absence(key, witness)? {
            None => chains.anchor_public(&ZERO_DIGEST),
            Some(opening) => {
                chains.disclosed(&opening.key, &opening.value_digest);
                chains.path(DOMAIN_BRANCH, &opening.path, true);
                chains.anchor();
            }
        }
        Ok(chains.finish())
    }

    fn range_program(
        schema: Digest,
        root: Digest,
        lower: &[u8],
        upper: Option<&[u8]>,
        entries: &[(&[u8], &[u8])],
        witness: &[u8],
    ) -> core::result::Result<Program, Reject> {
        let opened = Self::open_range(lower, upper, entries, witness)?;
        let mut chains = Chains::new(schema, root);
        fringe_program(&mut chains, DOMAIN_BRANCH, &opened, entries)?;
        Ok(chains.finish())
    }
}

/// Programs of the Merkle B-tree over a sponge profile. Absence is the empty
/// range `[key, key ‖ 0x00)`.
impl<P: AirPermutation> WitnessPrograms for MerkleBTree<AlgebraicSponge<P>> {
    /// The predecessor below the absent key and the successor above it.
    const ABSENCE_GADGETS: GadgetUse = GadgetUse {
        bit_scans: 0,
        comparisons: 2,
    };
    /// The predecessor below the lower bound and the successor at or above
    /// the upper bound.
    const RANGE_GADGETS: GadgetUse = GadgetUse {
        bit_scans: 0,
        comparisons: 2,
    };

    fn inclusion_program(
        schema: Digest,
        root: Digest,
        key: &[u8],
        value: &[u8],
        witness: &[u8],
    ) -> core::result::Result<Program, Reject> {
        let path = Self::open_inclusion(witness)?;
        let mut chains = Chains::new(schema, root);
        chains.entry(key, value, 0);
        chains.path(DOMAIN_PAGE_NODE, &path, false);
        chains.anchor();
        Ok(chains.finish())
    }

    fn absence_program(
        schema: Digest,
        root: Digest,
        key: &[u8],
        witness: &[u8],
    ) -> core::result::Result<Program, Reject> {
        let upper = super::immediate_successor(key);
        Self::range_program(schema, root, key, Some(&upper), &[], witness)
    }

    fn range_program(
        schema: Digest,
        root: Digest,
        lower: &[u8],
        upper: Option<&[u8]>,
        entries: &[(&[u8], &[u8])],
        witness: &[u8],
    ) -> core::result::Result<Program, Reject> {
        let opened = Self::open_range(lower, upper, entries, witness)?;
        let mut chains = Chains::new(schema, root);
        fringe_program(&mut chains, DOMAIN_PAGE_NODE, &opened, entries)?;
        Ok(chains.finish())
    }
}

/// The sponge over one end of a link: a key or a sentinel.
fn link_sponge(chains: &mut Chains, link: &Link) {
    let (domain, bytes) = link.preimage();
    chains.sponge(domain, bytes);
}

/// How a linked leaf's chain obtains the key digest of its successor.
#[derive(Clone, Copy)]
enum Successor {
    /// Carried by the witness and bound by the leaf hash alone.
    Carried,
    /// Hashed earlier in the program from statement bytes, kept in a register.
    Register(usize),
}

/// The chain of one linked leaf: its leaf digest, its link to the successor,
/// its address path and the root normalisation. The leaf's own key digest is
/// kept in `register`.
fn linked_chain(
    chains: &mut Chains,
    leaf: &LinkedLeaf,
    value: Option<&[u8]>,
    register: usize,
    successor: Successor,
) {
    match (&leaf.own, value) {
        (Link::Key(key), Some(value)) => chains.entry(key, value, register),
        (own, _) => {
            // A bracketing leaf: its value digest is disclosed, and is zero
            // for the lower sentinel.
            link_sponge(chains, own);
            chains.last().save = Some(register);
            chains.blocks.push(compress(
                DOMAIN_LEAF,
                0,
                false,
                Sibling::Public(leaf.value_digest),
                true,
            ));
        }
    }
    chains.blocks.push(compress(
        DOMAIN_LINK,
        0,
        false,
        match successor {
            Successor::Carried => Sibling::Private(leaf.next_digest),
            Successor::Register(register) => Sibling::Saved(register),
        },
        true,
    ));
    // The address is a digest, so the sides need no public binding.
    chains.path(DOMAIN_BRANCH, &leaf.path, false);
    chains.anchor();
}

/// Programs of the linked-leaf map over a sponge profile.
///
/// Absence is the bracketing leaf, whose two disclosed ends the verifier
/// compares with the statement. A range is the bracketing leaf and one chain
/// per claimed entry, written last leaf first: every leaf keeps its key digest
/// in one of two registers, where the chain of the leaf before it reads it as
/// its successor, so each key is hashed once and the successor of every leaf
/// is the next claimed key by constraint.
impl<P: AirPermutation> WitnessPrograms for LinkedLeafMap<AlgebraicSponge<P>> {
    /// The bracketing key below the absent key and its successor above it.
    const ABSENCE_GADGETS: GadgetUse = GadgetUse {
        bit_scans: 0,
        comparisons: 2,
    };
    /// The bracketing key below the lower bound and the last successor at or
    /// above the upper bound.
    const RANGE_GADGETS: GadgetUse = GadgetUse {
        bit_scans: 0,
        comparisons: 2,
    };

    fn inclusion_program(
        schema: Digest,
        root: Digest,
        key: &[u8],
        value: &[u8],
        witness: &[u8],
    ) -> core::result::Result<Program, Reject> {
        let mut leaf = Self::open_inclusion(key, witness)?;
        leaf.value_digest = value_digest::<AlgebraicSponge<P>>(value);
        let mut chains = Chains::new(schema, root);
        linked_chain(&mut chains, &leaf, Some(value), 0, Successor::Carried);
        Ok(chains.finish())
    }

    fn absence_program(
        schema: Digest,
        root: Digest,
        key: &[u8],
        witness: &[u8],
    ) -> core::result::Result<Program, Reject> {
        let (leaf, next) = Self::open_absence(key, witness)?;
        let mut chains = Chains::new(schema, root);
        link_sponge(&mut chains, &next);
        chains.last().save = Some(1);
        linked_chain(&mut chains, &leaf, None, 0, Successor::Register(1));
        Ok(chains.finish())
    }

    fn range_program(
        schema: Digest,
        root: Digest,
        lower: &[u8],
        upper: Option<&[u8]>,
        entries: &[(&[u8], &[u8])],
        witness: &[u8],
    ) -> core::result::Result<Program, Reject> {
        let (leaves, last) = Self::open_range(lower, upper, entries, witness)?;
        let mut chains = Chains::new(schema, root);
        // Leaf `index` keeps its key digest in register `index % 2`.
        link_sponge(&mut chains, &last);
        chains.last().save = Some(leaves.len() % 2);
        for (index, leaf) in leaves.iter().enumerate().rev() {
            let value = index.checked_sub(1).map(|claimed| entries[claimed].1);
            linked_chain(
                &mut chains,
                leaf,
                value,
                index % 2,
                Successor::Register((index + 1) % 2),
            );
        }
        Ok(chains.finish())
    }
}

/// Program of a table-level inclusion statement.
///
/// # Errors
/// The root is not a digest of the profile or the witness is not canonical.
pub fn inclusion_statement<E: WitnessPrograms>(
    schema: &PrototypeSchema,
    root: &[u8; DIGEST_BYTES],
    table: u32,
    key: &[u8],
    value: &[u8],
    witness: &[u8],
) -> core::result::Result<Program, Reject> {
    let root = root_digest::<E::Hash>(root).ok_or(Reject::NotProven)?;
    E::inclusion_program(
        schema.digest::<E::Hash>(),
        root,
        &composite_key(table, key),
        value,
        witness,
    )
}

/// Program of a table-level absence statement.
///
/// # Errors
/// The root is not a digest of the profile or the witness is not canonical.
pub fn absence_statement<E: WitnessPrograms>(
    schema: &PrototypeSchema,
    root: &[u8; DIGEST_BYTES],
    table: u32,
    key: &[u8],
    witness: &[u8],
) -> core::result::Result<Program, Reject> {
    let root = root_digest::<E::Hash>(root).ok_or(Reject::NotProven)?;
    E::absence_program(
        schema.digest::<E::Hash>(),
        root,
        &composite_key(table, key),
        witness,
    )
}

/// Program of a table-level complete-range statement. The claimed keys must
/// be strictly ascending inside the interval, as verification requires.
///
/// # Errors
/// The root is not a digest of the profile or the witness is not canonical.
pub fn range_statement<E: WitnessPrograms>(
    schema: &PrototypeSchema,
    root: &[u8; DIGEST_BYTES],
    table: u32,
    lower: &[u8],
    upper: Option<&[u8]>,
    entries: &[(&[u8], &[u8])],
    witness: &[u8],
) -> core::result::Result<Program, Reject> {
    let root = root_digest::<E::Hash>(root).ok_or(Reject::NotProven)?;
    let keys: Vec<Vec<u8>> = entries
        .iter()
        .map(|(key, _)| composite_key(table, key))
        .collect();
    let composite: Vec<(&[u8], &[u8])> = keys
        .iter()
        .zip(entries)
        .map(|(key, (_, value))| (key.as_slice(), *value))
        .collect();
    let (lower, upper) = composite_range(table, lower, upper);
    E::range_program(
        schema.digest::<E::Hash>(),
        root,
        &lower,
        upper.as_deref(),
        &composite,
        witness,
    )
}

/// Geometry of the as-built `BLAKE2b` compression gadget of the sealed q77
/// relation, read from its owner: the comparator for a byte-hash tree.
#[must_use]
pub const fn as_built_blake2b_gadget() -> (usize, usize, usize) {
    (
        crate::gadgets::compact_blake2b_air::ROW_COUNT,
        crate::gadgets::compact_blake2b_air::COLUMN_COUNT,
        crate::gadgets::compact_smt_air::PHYSICAL_HASH_ROWS,
    )
}

#[cfg(test)]
#[path = "circuit_tests.rs"]
mod tests;
