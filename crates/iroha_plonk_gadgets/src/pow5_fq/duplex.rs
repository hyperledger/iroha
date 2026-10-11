//! Transcript (duplex) mode on a Pow5 lane: squeezes that carry the state
//! on, as [`iroha_pasta::poseidon::Sponge`] does.
//!
//! # Semantics
//!
//! Bit for bit the native sponge: the state starts at `[2^64, 0, 0]`;
//! [`DuplexChip::absorb`] buffers a word; [`DuplexChip::squeeze`] absorbs the
//! buffer two words per permutation into words 1 and 2 (a short final chunk
//! `[x]` as `[x, 1]`; an even buffer length, zero included, adds one
//! permutation absorbing `[1, 0]`) and returns word 1. The state carries
//! over to the next squeeze. This is the snark-verifier
//! `PoseidonTranscript` sponge that the KAGEMUSHA transcript (spec 6.2) and
//! the base-field PIPA-R transcript (6.2b) run.
//!
//! # Layout and cost
//!
//! Squeezing `m` buffered words lays out `floor(m / 2) + 1` permutation
//! blocks of [`crate::poseidon::ROWS_PER_PERMUTATION`] rows. A continuing squeeze reads its
//! output through a *tap*: the auxiliary cell on the last row of the last
//! block, which the generic chip leaves free when it does not squeeze,
//! constrained by
//!
//! `q_tap (x - s1[next]) = 0` (degree 2)
//!
//! to word 1 of the state on the next block's row 0, which the last full
//! round's gate pins. A tap costs one advice cell and no row. The state a
//! continuing squeeze leaves sits on row 0 of the next block, which the next
//! squeeze permutes; a transcript that ends with a continuing squeeze (or a
//! [`DuplexChip::clear`]) leaves that block reserved with only its row 0
//! used. The final squeeze of a transcript
//! ([`DuplexChip::squeeze_and_clear`]) uses the generic squeeze gate
//! instead, so it reserves no block for a state nobody reads: a transcript
//! of squeezes over `m_1, m_2, ...` words costs exactly
//! `sum_i (floor(m_i / 2) + 1)` blocks and one tap per continuing squeeze.
//!
//! Domain hashes ([`SpongeChip::hash`]) may share the lane between
//! transcripts; [`DuplexChip::sponge_mut`] refuses while a transcript state
//! is live, because a hash would take the block that state must continue
//! in.

use iroha_pasta::poseidon::PoseidonField;
use iroha_plonk::{
    cs::{ConstraintSystem, Rotation},
    frontend::{Error, Region},
};

use crate::{
    cells::{Word, assign_word},
    phase::{Enable, PhaseColumns},
    poseidon::{
        Absorb, AbsorbInput, Pow5Chip, Pow5Columns, Pow5State, RoundConstantColumns, SpongeChip,
        SpongeConfig, raw_initial_state, raw_permutations,
    },
};

/// Permutations of one squeeze of `buffered` words.
#[must_use]
pub const fn squeeze_permutations(buffered: usize) -> usize {
    raw_permutations(buffered)
}

/// The absorbed blocks of `elements` with the sponge padding: pairs, then
/// `[x, 1]` for a short final chunk or `[1, 0]` for an even length.
fn padded_blocks<'w, F: PoseidonField>(
    elements: &[AbsorbInput<'w, F>],
) -> Vec<[AbsorbInput<'w, F>; 2]> {
    let chunks = elements.chunks_exact(2);
    let tail = match chunks.remainder() {
        [last] => [*last, AbsorbInput::Constant(F::ONE)],
        _ => [
            AbsorbInput::Constant(F::ONE),
            AbsorbInput::Constant(F::ZERO),
        ],
    };
    let mut blocks: Vec<[AbsorbInput<'w, F>; 2]> =
        chunks.map(|chunk| [chunk[0], chunk[1]]).collect();
    blocks.push(tail);
    blocks
}

/// A Pow5 lane configured as a KAGEMUSHA sponge plus the tap gate of the
/// transcript mode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DuplexConfig<F> {
    sponge: SpongeConfig<F>,
    q_tap: Enable,
}

impl<F: PoseidonField> DuplexConfig<F> {
    /// Configures a lane on `lane` with `round_constants` (shareable with
    /// other lanes), folding the domain-hash prefixes `(domain, arity)` of
    /// `folded`, and the tap gate.
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        lane: Pow5Columns,
        round_constants: RoundConstantColumns,
        folded: &[(u64, usize)],
    ) -> Self {
        let sponge = SpongeConfig::configure(meta, lane, round_constants, folded);
        let q_tap = meta.selector().into();
        Self::configure_tap(meta, lane, sponge, q_tap)
    }

    /// Configures transcript mode on the shared compact phase columns.
    /// Every domain and arity is absorbed explicitly into the raw sponge.
    pub fn configure_phased(
        meta: &mut ConstraintSystem<F>,
        lane: Pow5Columns,
        phases: PhaseColumns,
    ) -> Self {
        let sponge = SpongeConfig::configure_phased(meta, lane, phases);
        Self::configure_tap(meta, lane, sponge, phases.enable(2, Some((5, 2, 2))))
    }

    fn configure_tap(
        meta: &mut ConstraintSystem<F>,
        lane: Pow5Columns,
        sponge: SpongeConfig<F>,
        q_tap: Enable,
    ) -> Self {
        meta.create_gate("duplex tap", |cells| {
            let q = q_tap.query(cells);
            let tap = cells.query_advice(lane.aux, Rotation::cur());
            let word1 = cells.query_advice(lane.state[1], Rotation::next());
            vec![("x - s1[next]", q * (tap - word1))]
        });
        Self { sponge, q_tap }
    }

    /// The sponge configuration of the lane.
    #[must_use]
    pub const fn sponge(&self) -> &SpongeConfig<F> {
        &self.sponge
    }
}

/// A buffered transcript element.
#[derive(Clone, Debug)]
enum Pending<F: PoseidonField> {
    /// A cell, copied into the lane when absorbed.
    Word(Word<F>),
    /// A constant, pinned through the constants column.
    Constant(F),
}

impl<F: PoseidonField> Pending<F> {
    /// The lane input.
    const fn input(&self) -> AbsorbInput<'_, F> {
        match self {
            Self::Word(word) => AbsorbInput::Word(word),
            Self::Constant(constant) => AbsorbInput::Constant(*constant),
        }
    }
}

/// The transcript-mode sponge on one lane.
#[derive(Debug)]
pub struct DuplexChip<F: PoseidonField> {
    sponge: SpongeChip<F>,
    q_tap: Enable,
    state: Option<Pow5State<F>>,
    buffer: Vec<Pending<F>>,
}

impl<F: PoseidonField> DuplexChip<F> {
    /// A fresh transcript whose lane starts at row 0.
    #[must_use]
    pub fn new(config: DuplexConfig<F>) -> Self {
        Self {
            sponge: SpongeChip::new(config.sponge),
            q_tap: config.q_tap,
            state: None,
            buffer: Vec::new(),
        }
    }

    /// Constructs an empty lane confined to `[0,end_row)`.
    #[must_use]
    pub fn bounded(config: DuplexConfig<F>, end_row: usize) -> Self {
        let mut chip = Self::new(config);
        chip.sponge
            .lane_mut()
            .bound_rows(end_row)
            .expect("new lane is empty");
        chip
    }

    /// Starts an empty transcript after a structurally reserved prefix.
    ///
    /// # Errors
    /// The lane is nonempty or the prefix exceeds its end bound.
    pub fn start_at(&mut self, row: usize) -> Result<(), Error> {
        self.sponge.lane_mut().start_at(row)
    }

    /// Routes absorbed constants through a caller-reserved arithmetic lane.
    /// Copies bind the fixed-coefficient result to the exact transcript cell.
    ///
    /// # Errors
    /// The source is not a bounded shared coefficient-only lane containing
    /// the transcript copy port, or this transcript already reserved rows.
    pub fn with_constant_source(mut self, source: crate::GlueChip<F>) -> Result<Self, Error> {
        self.sponge.lane_mut().set_constant_source(source)?;
        Ok(self)
    }

    /// The lane.
    #[must_use]
    pub const fn lane(&self) -> &Pow5Chip<F> {
        self.sponge.lane()
    }

    /// The words buffered since the last squeeze.
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.buffer.len()
    }

    /// Whether the transcript is fresh: no live state and nothing buffered.
    #[must_use]
    pub fn is_clear(&self) -> bool {
        self.state.is_none() && self.buffer.is_empty()
    }

    /// Buffers `word` (copied into the lane at the next squeeze).
    pub fn absorb(&mut self, word: &Word<F>) {
        self.buffer.push(Pending::Word(word.clone()));
    }

    /// Buffers every word of `words`.
    pub fn absorb_words(&mut self, words: &[Word<F>]) {
        self.buffer
            .extend(words.iter().map(|word| Pending::Word(word.clone())));
    }

    /// Buffers the constant `value` (pinned through the constants column).
    pub fn absorb_constant(&mut self, value: F) {
        self.buffer.push(Pending::Constant(value));
    }

    /// Drops the buffer and the state: the next squeeze starts a new
    /// transcript from `[2^64, 0, 0]` (native [`Sponge::clear`]). A live
    /// state keeps its block.
    ///
    /// [`Sponge::clear`]: iroha_pasta::poseidon::Sponge::clear
    pub fn clear(&mut self) {
        self.state = None;
        self.buffer.clear();
    }

    /// The sponge, for domain hashes between transcripts.
    ///
    /// # Errors
    ///
    /// [`Error::Synthesis`] while the transcript is not clear: a hash would
    /// take the block its state must continue in.
    pub fn sponge_mut(&mut self) -> Result<&mut SpongeChip<F>, Error> {
        if self.is_clear() {
            Ok(&mut self.sponge)
        } else {
            Err(Error::Synthesis)
        }
    }

    /// Absorbs the buffer and returns word 1 of the state, which carries on
    /// (native [`Sponge::squeeze`]): `floor(m / 2) + 1` permutation blocks
    /// for `m` buffered words and one tap cell; the state stays on row 0 of
    /// the next block.
    ///
    /// [`Sponge::squeeze`]: iroha_pasta::poseidon::Sponge::squeeze
    ///
    /// # Errors
    ///
    /// [`Error`] from the layout, including [`Error::Synthesis`] when another
    /// user of the lane took the block the state continues in.
    pub fn squeeze(&mut self, region: &mut Region<'_, F>) -> Result<Word<F>, Error> {
        self.absorb_buffer(region, false)
    }

    /// Absorbs the buffer, returns word 1 and clears the transcript (native
    /// `squeeze` then `clear`). The last block uses the squeeze gate, so no
    /// block is reserved for the dropped state and no tap is needed.
    ///
    /// # Errors
    ///
    /// As [`Self::squeeze`].
    pub fn squeeze_and_clear(&mut self, region: &mut Region<'_, F>) -> Result<Word<F>, Error> {
        self.absorb_buffer(region, true)
    }

    /// Lays out the buffered blocks from the live state (or a new start) and
    /// returns word 1 after the last one.
    fn absorb_buffer(&mut self, region: &mut Region<'_, F>, last: bool) -> Result<Word<F>, Error> {
        let pending = core::mem::take(&mut self.buffer);
        let inputs: Vec<AbsorbInput<'_, F>> = pending.iter().map(Pending::input).collect();
        let mut blocks = padded_blocks(&inputs);
        let final_block = blocks.pop().ok_or(Error::Synthesis)?;
        let lane = self.sponge.lane_mut();
        let mut state = match self.state.take() {
            Some(state) => state,
            None => lane.start(region, raw_initial_state::<F>())?,
        };
        for block in blocks {
            state = lane.permute(region, state, Absorb::Block(block))?;
        }
        if last {
            return lane.squeeze(region, state, Absorb::Block(final_block));
        }
        let next = lane.permute(region, state, Absorb::Block(final_block))?;
        let row = lane
            .block_row(next.block())?
            .checked_sub(1)
            .ok_or(Error::BoundsFailure)?;
        self.q_tap.enable(region, row)?;
        let aux = lane.config().lane().aux;
        let output = assign_word(region, aux, row, next.value().map(|state| state[1]))?;
        self.state = Some(next);
        Ok(output)
    }
}

/// The native transcript reference: the challenges of `script`, where each
/// entry buffers its words and then squeezes once, with the state carried
/// on ([`iroha_pasta::poseidon::Sponge`]).
#[must_use]
pub fn duplex_native<F: PoseidonField>(script: &[Vec<F>]) -> Vec<F> {
    let mut sponge = iroha_pasta::poseidon::Sponge::<F>::new();
    script
        .iter()
        .map(|words| {
            sponge.update(words);
            sponge.squeeze()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use ff::Field as _;
    use iroha_pasta::{
        Fp, Fq,
        poseidon::{Sponge, hash, permute},
    };

    use super::*;
    use crate::poseidon::permute_native;

    fn constants<F: PoseidonField>(blocks: &[[AbsorbInput<'_, F>; 2]]) -> Vec<[F; 2]> {
        blocks
            .iter()
            .map(|block| {
                block.map(|input| match input {
                    AbsorbInput::Constant(value) => value,
                    AbsorbInput::Word(_) => unreachable!("constants only"),
                })
            })
            .collect()
    }

    #[test]
    fn padding_matches_the_native_sponge() {
        let c = |v: u64| AbsorbInput::Constant(Fq::from(v));
        let one = Fq::ONE;
        assert_eq!(constants(&padded_blocks::<Fq>(&[])), vec![[one, Fq::ZERO]]);
        assert_eq!(
            constants(&padded_blocks(&[c(7)])),
            vec![[Fq::from(7u64), one]]
        );
        assert_eq!(
            constants(&padded_blocks(&[c(7), c(8)])),
            vec![[Fq::from(7u64), Fq::from(8u64)], [one, Fq::ZERO]]
        );
        assert_eq!(
            constants(&padded_blocks(&[c(7), c(8), c(9)])),
            vec![[Fq::from(7u64), Fq::from(8u64)], [Fq::from(9u64), one]]
        );
        for length in 0..9 {
            assert_eq!(
                padded_blocks(&vec![c(1); length]).len(),
                squeeze_permutations(length)
            );
        }
        // The blocks reproduce Sponge::squeeze from the raw state.
        let words = [Fq::from(3u64), -Fq::ONE, Fq::from(5u64)];
        let inputs = words.map(AbsorbInput::Constant);
        let mut state = raw_initial_state::<Fq>();
        for block in constants(&padded_blocks(&inputs)) {
            state = permute_native(state, block);
        }
        assert_eq!(state[1], hash(&words));
    }

    fn native_transcript_carries_the_state<F: PoseidonField>() {
        let script = vec![
            vec![F::from(1u64)],
            vec![],
            vec![F::from(2u64), F::from(3u64)],
        ];
        let challenges = duplex_native(&script);
        // By hand: the state carries over between squeezes.
        let mut state = raw_initial_state::<F>();
        state = permute_native(state, [F::from(1u64), F::ONE]);
        assert_eq!(challenges[0], state[1]);
        state = permute_native(state, [F::ONE, F::ZERO]);
        assert_eq!(challenges[1], state[1]);
        state = permute_native(state, [F::from(2u64), F::from(3u64)]);
        state = permute_native(state, [F::ONE, F::ZERO]);
        assert_eq!(challenges[2], state[1]);
        let mut sponge = Sponge::<F>::new();
        sponge.update(&[F::from(1u64)]);
        assert_eq!(sponge.squeeze(), challenges[0]);
        let mut plain = raw_initial_state::<F>();
        plain[1] += F::ONE;
        permute(&mut plain);
        assert_eq!(duplex_native::<F>(&[vec![]]), vec![plain[1]]);
    }

    #[test]
    fn native_reference_carries_the_state_on_both_fields() {
        native_transcript_carries_the_state::<Fq>();
        native_transcript_carries_the_state::<Fp>();
    }

    #[test]
    fn configure_adds_one_degree_two_tap_gate() {
        let mut meta = ConstraintSystem::<Fq>::new();
        let lane = Pow5Columns::allocate(&mut meta);
        let round_constants = RoundConstantColumns::allocate(&mut meta);
        let config = DuplexConfig::configure(&mut meta, lane, round_constants, &[(9, 2)]);
        assert!(config.sponge().is_folded(9, 2));
        let tap = meta
            .gates()
            .iter()
            .filter(|gate| gate.name() == "duplex tap")
            .collect::<Vec<_>>();
        assert_eq!(tap.len(), 1);
        assert_eq!(tap[0].polynomials().len(), 1);
        assert_eq!(tap[0].polynomials()[0].degree(), 2);
        assert_eq!(meta.degree(), 6);
        let chip = DuplexChip::new(config);
        assert!(chip.is_clear());
        assert_eq!(chip.buffered(), 0);
        assert_eq!(chip.lane().next_block(), 0);
    }

    #[test]
    fn buffering_and_clearing() {
        let mut meta = ConstraintSystem::<Fq>::new();
        let lane = Pow5Columns::allocate(&mut meta);
        let round_constants = RoundConstantColumns::allocate(&mut meta);
        let config = DuplexConfig::configure(&mut meta, lane, round_constants, &[]);
        let mut chip = DuplexChip::new(config);
        chip.absorb_constant(Fq::from(4u64));
        assert_eq!(chip.buffered(), 1);
        assert!(!chip.is_clear());
        assert_eq!(chip.sponge_mut().map(|_| ()), Err(Error::Synthesis));
        chip.absorb_words(&[]);
        assert_eq!(chip.buffered(), 1);
        chip.clear();
        assert!(chip.is_clear());
        assert!(chip.sponge_mut().is_ok());
        let pending = Pending::Constant(Fq::from(6u64));
        assert!(matches!(pending.input(), AbsorbInput::Constant(v) if v == Fq::from(6u64)));
    }
    #[derive(Clone)]
    struct OffsetDuplex<F: PoseidonField> {
        offset: usize,
        marker: core::marker::PhantomData<F>,
    }
    impl<F: PoseidonField> iroha_plonk::frontend::Circuit<F> for OffsetDuplex<F> {
        type Config = (
            DuplexConfig<F>,
            iroha_plonk::cs::Column<iroha_plonk::cs::Instance>,
        );
        type FloorPlanner = iroha_plonk::frontend::SimpleFloorPlanner;
        type Params = ();
        fn without_witnesses(&self) -> Self {
            self.clone()
        }
        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let lane = Pow5Columns::allocate(meta);
            let constants = RoundConstantColumns::allocate(meta);
            let constant = meta.fixed_column();
            meta.enable_constant(constant);
            let config = DuplexConfig::configure(meta, lane, constants, &[]);
            let public = meta.instance_column(3);
            meta.enable_equality(public);
            (config, public)
        }
        fn synthesize(
            &self,
            (config, public): Self::Config,
            mut layouter: impl iroha_plonk::frontend::Layouter<F>,
        ) -> Result<(), Error> {
            let mut chip = DuplexChip::bounded(config, 1020);
            chip.start_at(self.offset)?;
            let outputs = layouter.assign_region(
                || "offset continuing duplex",
                |mut region| {
                    let mut out = Vec::new();
                    for words in [vec![F::from(3)], vec![], vec![F::from(5), F::from(7)]] {
                        for word in words {
                            chip.absorb_constant(word);
                        }
                        out.push(chip.squeeze(&mut region)?);
                    }
                    assert!(chip.start_at(0).is_err());
                    Ok(out)
                },
            )?;
            for (index, word) in outputs.iter().enumerate() {
                layouter.constrain_instance(word.cell(), public, index)?;
            }
            Ok(())
        }
    }
    fn offset_case<F: PoseidonField>() {
        use iroha_plonk::frontend::{Circuit, synthesize};
        let public = [duplex_native(&[
            vec![F::from(3)],
            vec![],
            vec![F::from(5), F::from(7)],
        ])];
        for offset in [0, 16, 37] {
            let circuit = OffsetDuplex::<F> {
                offset,
                marker: core::marker::PhantomData,
            };
            let report = iroha_plonk::check::check_circuit(
                &circuit,
                10,
                &public,
                iroha_plonk::check::CheckMode::Strict,
            )
            .unwrap();
            assert!(report.is_satisfied(), "{:?}", report.failures().first());
            let known = synthesize(&circuit, 10, Some(&public)).unwrap();
            let unknown = synthesize(&circuit.without_witnesses(), 10, None).unwrap();
            assert_eq!(known.tables.fixed(), unknown.tables.fixed());
            assert_eq!(known.tables.permutation(), unknown.tables.permutation());
            assert_eq!(
                known.tables.advice_assigned(),
                unknown.tables.advice_assigned()
            );
        }
    }
    #[test]
    fn offset_duplex_continuing_taps_match_native_both_fields() {
        offset_case::<Fp>();
        offset_case::<Fq>();
    }
}
