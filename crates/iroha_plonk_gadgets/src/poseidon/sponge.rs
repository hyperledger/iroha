//! The KAGEMUSHA sponge on a [`Pow5Chip`] lane.
//!
//! # Semantics
//!
//! Bit for bit the native sponge of [`iroha_pasta::poseidon`] (the vendored
//! snark-verifier `NativeLoader` semantics recorded in
//! `fixtures/native_prover/kats_v1.json`):
//!
//! - the state starts at `[2^64, 0, 0]`;
//! - the buffered input is absorbed two words per permutation into words 1
//!   and 2;
//! - a short final chunk `[x]` is absorbed as `[x, 1]`; when the input length
//!   is even (zero included) one more permutation absorbs `[1, 0]`;
//! - the output is word 1.
//!
//! [`SpongeChip::hash_raw`] is [`iroha_pasta::poseidon::hash`];
//! [`SpongeChip::hash`] is [`iroha_pasta::poseidon::hash_with_domain`] (the
//! KAGEMUSHA domain hash): the preimage is prefixed by the domain word and
//! the input arity. Padding words, the domain and the arity are
//! constants pinned through the constants column; inputs are copied into
//! the lane.
//!
//! # Folded prefixes
//!
//! The first chunk of a domain-prefixed hash is the constant `[domain,
//! arity]`, so the state after its permutation is a constant of the circuit.
//! A [`SpongeConfig`] configured with `(domain, arity)` starts such hashes
//! from that state (a start gate whose constants are part of the circuit
//! description) and saves one permutation; the digest is unchanged. Hashes
//! whose prefix was not configured absorb the prefix in circuit.
//!
//! A hash of `m` buffered words costs `floor(m / 2) + 1` permutations of 37
//! rows ([`raw_permutations`], [`domain_permutations`]).

use iroha_pasta::poseidon::{PoseidonField, WIDTH, permute};
use iroha_plonk::{
    cs::ConstraintSystem,
    frontend::{Error, Region},
};

use super::pow5::{Absorb, AbsorbInput, Pow5Chip, Pow5Columns, Pow5Config, RoundConstantColumns};
use crate::cells::Word;

/// Permutations of the raw sponge over `elements` buffered words.
#[must_use]
pub const fn raw_permutations(elements: usize) -> usize {
    elements / 2 + 1
}

/// Permutations of a domain-prefixed hash of `arity` inputs, with or without
/// a folded prefix.
#[must_use]
pub const fn domain_permutations(arity: usize, folded: bool) -> usize {
    if folded {
        raw_permutations(arity)
    } else {
        raw_permutations(arity.saturating_add(2))
    }
}

/// The initial sponge state `[2^64, 0, 0]`.
#[must_use]
pub fn raw_initial_state<F: PoseidonField>() -> [F; WIDTH] {
    [F::from_u128(1_u128 << 64), F::ZERO, F::ZERO]
}

/// The state after absorbing the prefix chunk `[domain, arity]`.
#[must_use]
pub fn folded_state<F: PoseidonField>(domain: u64, arity: usize) -> [F; WIDTH] {
    let mut state = raw_initial_state::<F>();
    state[1] += F::from(domain);
    state[2] += F::from(arity_word(arity));
    permute(&mut state);
    state
}

/// The arity word (in-memory lengths always fit a `u64`).
fn arity_word(arity: usize) -> u64 {
    u64::try_from(arity).unwrap_or(u64::MAX)
}

/// A Pow5 lane configured as a KAGEMUSHA sponge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpongeConfig<F> {
    pow5: Pow5Config<F>,
    folded: Vec<(u64, usize)>,
}

impl<F: PoseidonField> SpongeConfig<F> {
    /// Configures a sponge lane on `lane` with `round_constants` (which other
    /// lanes may share), folding the prefixes `(domain, arity)` of
    /// `folded`.
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        lane: Pow5Columns,
        round_constants: RoundConstantColumns,
        folded: &[(u64, usize)],
    ) -> Self {
        let mut states = vec![raw_initial_state::<F>()];
        let mut prefixes = Vec::with_capacity(folded.len());
        for (domain, arity) in folded {
            if !prefixes.contains(&(*domain, *arity)) {
                prefixes.push((*domain, *arity));
                states.push(folded_state::<F>(*domain, *arity));
            }
        }
        Self {
            pow5: Pow5Config::configure(meta, lane, round_constants, &states),
            folded: prefixes,
        }
    }

    /// The lane configuration.
    #[must_use]
    pub const fn pow5(&self) -> &Pow5Config<F> {
        &self.pow5
    }

    /// Whether `(domain, arity)` starts from a folded state.
    #[must_use]
    pub fn is_folded(&self, domain: u64, arity: usize) -> bool {
        self.folded.contains(&(domain, arity))
    }
}

/// The KAGEMUSHA sponge chip.
#[derive(Clone, Debug)]
pub struct SpongeChip<F: PoseidonField> {
    lane: Pow5Chip<F>,
    folded: Vec<(u64, usize)>,
}

impl<F: PoseidonField> SpongeChip<F> {
    /// A sponge whose lane starts at row 0.
    #[must_use]
    pub fn new(config: SpongeConfig<F>) -> Self {
        Self {
            folded: config.folded,
            lane: Pow5Chip::new(config.pow5),
        }
    }

    /// The lane.
    #[must_use]
    pub const fn lane(&self) -> &Pow5Chip<F> {
        &self.lane
    }

    /// The lane, for raw permutations between hashes (they share its
    /// blocks).
    pub const fn lane_mut(&mut self) -> &mut Pow5Chip<F> {
        &mut self.lane
    }

    /// The permutations [`Self::hash`] lays out for `(domain, arity)`.
    #[must_use]
    pub fn permutations(&self, domain: u64, arity: usize) -> usize {
        domain_permutations(arity, self.folded.contains(&(domain, arity)))
    }

    /// `hash_with_domain(domain, inputs)`.
    ///
    /// # Errors
    ///
    /// [`Error`] from the layout (for example a lane longer than the usable
    /// rows).
    pub fn hash(
        &mut self,
        region: &mut Region<'_, F>,
        domain: u64,
        inputs: &[AbsorbInput<'_, F>],
    ) -> Result<Word<F>, Error> {
        if self.folded.contains(&(domain, inputs.len())) {
            let initial = folded_state::<F>(domain, inputs.len());
            return self.absorb_all(region, initial, inputs);
        }
        let mut elements = Vec::with_capacity(inputs.len().saturating_add(2));
        elements.push(AbsorbInput::Constant(F::from(domain)));
        elements.push(AbsorbInput::Constant(F::from(arity_word(inputs.len()))));
        elements.extend_from_slice(inputs);
        self.absorb_all(region, raw_initial_state::<F>(), &elements)
    }

    /// `hash_with_domain(domain, words)`.
    ///
    /// # Errors
    ///
    /// As [`Self::hash`].
    pub fn hash_words(
        &mut self,
        region: &mut Region<'_, F>,
        domain: u64,
        words: &[Word<F>],
    ) -> Result<Word<F>, Error> {
        let inputs: Vec<AbsorbInput<'_, F>> = words.iter().map(AbsorbInput::Word).collect();
        self.hash(region, domain, &inputs)
    }

    /// The raw sponge `hash(inputs)`.
    ///
    /// # Errors
    ///
    /// As [`Self::hash`].
    pub fn hash_raw(
        &mut self,
        region: &mut Region<'_, F>,
        inputs: &[AbsorbInput<'_, F>],
    ) -> Result<Word<F>, Error> {
        self.absorb_all(region, raw_initial_state::<F>(), inputs)
    }

    /// Absorbs `elements` with the KAGEMUSHA padding from `initial` and
    /// squeezes word 1.
    fn absorb_all(
        &mut self,
        region: &mut Region<'_, F>,
        initial: [F; WIDTH],
        elements: &[AbsorbInput<'_, F>],
    ) -> Result<Word<F>, Error> {
        let chunks = elements.chunks_exact(2);
        let tail = match chunks.remainder() {
            [last] => [*last, AbsorbInput::Constant(F::ONE)],
            _ => [
                AbsorbInput::Constant(F::ONE),
                AbsorbInput::Constant(F::ZERO),
            ],
        };
        let mut blocks: Vec<[AbsorbInput<'_, F>; 2]> =
            chunks.map(|chunk| [chunk[0], chunk[1]]).collect();
        blocks.push(tail);
        let mut state = self.lane.start(region, initial)?;
        let last = blocks.len() - 1;
        for (index, block) in blocks.into_iter().enumerate() {
            if index == last {
                return self.lane.squeeze(region, state, Absorb::Block(block));
            }
            state = self.lane.permute(region, state, Absorb::Block(block))?;
        }
        Err(Error::Synthesis)
    }
}

#[cfg(test)]
mod tests {
    use iroha_pasta::{
        Fp, Fq,
        poseidon::{PoseidonField, hash_with_domain},
    };

    use super::*;

    #[test]
    fn permutation_counts() {
        assert_eq!(raw_permutations(0), 1);
        assert_eq!(raw_permutations(1), 1);
        assert_eq!(raw_permutations(2), 2);
        assert_eq!(raw_permutations(3), 2);
        // M7: `(fields + 2) / 2 + 1`; folding saves the prefix permutation.
        for (fields, m7) in [(32, 18), (24, 14), (10, 7), (6, 5), (11, 7)] {
            assert_eq!(domain_permutations(fields, false), m7, "{fields} fields");
            assert_eq!(domain_permutations(fields, true), m7 - 1, "{fields} fields");
        }
    }

    fn folded_state_continues_the_native_sponge<F: PoseidonField>() {
        // Absorbing [x, 1] after the folded prefix is hash_with_domain(d, [x]).
        let domain = u64::from_le_bytes(*b"kgmnode1");
        let x = F::from(7u64);
        let mut state = folded_state::<F>(domain, 1);
        state[1] += x;
        state[2] += F::ONE;
        permute(&mut state);
        assert_eq!(state[1], hash_with_domain(domain, &[x]));
        assert_eq!(raw_initial_state::<F>()[0], F::from_u128(1 << 64));
        assert_eq!(arity_word(3), 3);
    }

    #[test]
    fn folded_states_match_the_native_sponge() {
        folded_state_continues_the_native_sponge::<Fp>();
        folded_state_continues_the_native_sponge::<Fq>();
    }

    #[test]
    fn configured_prefixes_are_folded_once() {
        // Test-only domain words with arbitrary arities (no protocol domain).
        let statement = u64::from_le_bytes(*b"sptest_1");
        let chain = u64::from_le_bytes(*b"sptest_2");
        let mut meta = ConstraintSystem::<Fp>::new();
        let lane = Pow5Columns::allocate(&mut meta);
        let round_constants = RoundConstantColumns::allocate(&mut meta);
        // A repeated prefix is folded once.
        let config = SpongeConfig::configure(
            &mut meta,
            lane,
            round_constants,
            &[(statement, 25), (chain, 8), (statement, 25)],
        );
        assert!(config.is_folded(statement, 25));
        assert!(config.is_folded(chain, 8));
        // Another arity or domain is not.
        assert!(!config.is_folded(statement, 24));
        assert!(!config.is_folded(u64::from_le_bytes(*b"sptest_3"), 24));
        let sponge = SpongeChip::new(config.clone());
        assert_eq!(sponge.permutations(statement, 25), 13);
        assert_eq!(sponge.permutations(statement, 24), 14);
        assert_eq!(config.pow5(), sponge.lane().config());
    }
}
