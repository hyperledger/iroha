//! Load's private state transition, with native receipt finality before Advance.
//! A binds the authorized receipt terms and authenticates the recovery-map insertion.

use iroha_plonk_gadgets::Word;

use super::*;
use crate::operation_relation::map_effects::{MapState, MapTransition};

/// Canonical G1 state opening and private 18-word sigma projection.
///
/// Load and Archive may use core burned/pending roots and an empty credit root
/// in this projection before folding. This witness is not an authenticated Ω
/// object. Their A relations independently authenticate the actual predecessor
/// and adjusted state. Consuming sigma relations require that actual prefix.
#[derive(Clone, Copy, Debug)]
pub struct StateWitness {
    /// Exact 33-field state core.
    pub core: [Fp; CORE_FIELDS],
    /// Exact eight-field rest.
    pub rest: [Fp; REST_FIELDS],
    /// Exact 18-field private projection for this operation's sigma relation.
    pub lineage: [Fp; 18],
}
impl From<&BootstrapWitness> for StateWitness {
    fn from(source: &BootstrapWitness) -> Self {
        Self {
            core: source.core,
            rest: source.rest,
            lineage: source.lineage,
        }
    }
}

/// Load's original/successor openings and exact public statement preimage.
#[derive(Clone, Copy, Debug)]
pub struct LoadWitness {
    /// Original core/rest opening; Load does not require a folded predecessor.
    pub predecessor: StateWitness,
    /// Newly committed state.
    pub successor: StateWitness,
    /// Exact 26-field Load statement.
    pub statement: [Fp; 26],
}

/// Load arithmetic, continuity and unchanged fields on the fixed k12 sigma class.
///
/// Native BLS verification authenticates receipt finality before the wallet signs Advance.
/// A binds that authorized receipt's exact amount, ordinal and online charge and proves
/// the recovery-map insertion; it does not independently verify BLS finality. The sigma
/// opens both heads and binds the carried recovery root; it does not replace A.
#[derive(Clone, Copy, Debug)]
pub struct LoadCircuit {
    witness: LoadWitness,
    known: bool,
}
impl LoadCircuit {
    /// Carry the complete witness to the circuit; this does not accept a Load.
    #[must_use]
    pub const fn new(witness: &LoadWitness) -> Self {
        Self {
            witness: *witness,
            known: true,
        }
    }

    /// One bounded public statement digest, computed from the original fields.
    #[must_use]
    pub fn instances(&self) -> [Vec<Fp>; 1] {
        [vec![hash_with_domain(
            STATEMENT_DOMAIN,
            &self.witness.statement,
        )]]
    }

    /// Exact instance membership for native PIPA-R key generation.
    #[must_use]
    pub const fn instance_types() -> [InstanceType; 1] {
        [InstanceType::Bounded]
    }
}
pub(super) const BASE_HASH_ROWS: usize = (2
    * (domain_permutations(CORE_FIELDS + 1, true) + domain_permutations(REST_FIELDS, true))
    + domain_permutations(26, true))
    * ROWS_PER_PERMUTATION;
pub(super) const STATE_WORDS: usize = CORE_FIELDS + REST_FIELDS + 18;

pub(super) fn state(
    uint: &mut UintChip<'_, Fp>,
    sponge: &mut SpongeChip<Fp>,
    region: &mut iroha_plonk::frontend::Region<'_, Fp>,
    words: &[Word<Fp>],
) -> Result<(StateCells, LineagePublicCells), Error> {
    if words.len() != STATE_WORDS {
        return Err(Error::Synthesis);
    }
    let state = StateCells::constrain(
        uint,
        sponge,
        region,
        &core::array::from_fn(|i| words[i].clone()),
        &core::array::from_fn(|i| words[CORE_FIELDS + i].clone()),
    )?;
    let lineage = LineagePublicCells::constrain(
        uint,
        region,
        &core::array::from_fn(|i| words[CORE_FIELDS + REST_FIELDS + i].clone()),
    )?;
    Ok((state, lineage))
}
impl Circuit<Fp> for LoadCircuit {
    type Config = AdminConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..*self
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        BootstrapCircuit::configure(meta)
    }
    fn synthesize(&self, config: Self::Config, layouter: impl Layouter<Fp>) -> Result<(), Error> {
        Transition {
            predecessor: &self.witness.predecessor,
            successor: &self.witness.successor,
            statement: &self.witness.statement,
            variant: Variant::Load,
            known: self.known,
        }
        .synthesize(config, layouter)
    }
}

/// Shared fixed-variant synthesis; callers pin the variant in their Rust type.
pub(super) struct Transition<'a> {
    pub predecessor: &'a StateWitness,
    pub successor: &'a StateWitness,
    pub statement: &'a [Fp; 26],
    pub variant: Variant,
    pub known: bool,
}
impl Transition<'_> {
    pub(super) fn synthesize(
        &self,
        config: AdminConfig,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let (label, hash_rows) = match self.variant {
            Variant::Load => ("Load administrative sigma", BASE_HASH_ROWS),
            Variant::ArchiveReceive => ("ArchiveSent administrative sigma", BASE_HASH_ROWS),
            Variant::Retiring => ("Retiring administrative sigma", BASE_HASH_ROWS),
            Variant::Unload => (
                "Unload administrative sigma",
                // Bootstrap's configuration does not fold the nullifier prefix.
                BASE_HASH_ROWS + domain_permutations(5, false) * ROWS_PER_PERMUTATION,
            ),
            _ => return Err(Error::Synthesis),
        };
        let mut glue = GlueChip::starting_at(config.glue, hash_rows);
        let mut range = RunningSumChip::new(config.range);
        let mut sponge = SpongeChip::new(config.sponge);
        range.load_table(&mut layouter)?;
        let digest = layouter.assign_region(
            || label,
            |mut region| {
                let before = self.predecessor;
                let after = self.successor;
                let values = before
                    .core
                    .iter()
                    .chain(&before.rest)
                    .chain(&before.lineage)
                    .chain(&after.core)
                    .chain(&after.rest)
                    .chain(&after.lineage)
                    .chain(self.statement)
                    .map(|v| {
                        if self.known {
                            Value::known(*v)
                        } else {
                            Value::unknown()
                        }
                    })
                    .collect::<Vec<_>>();
                let words = glue.witnesses(&mut region, &values)?;
                let mut uint = UintChip::new(&mut glue, &mut range);
                let (before, previous) =
                    state(&mut uint, &mut sponge, &mut region, &words[..STATE_WORDS])?;
                let (after, successor) = state(
                    &mut uint,
                    &mut sponge,
                    &mut region,
                    &words[STATE_WORDS..2 * STATE_WORDS],
                )?;
                let statement = StatementCells::constrain(
                    &mut uint,
                    &mut sponge,
                    &mut region,
                    self.variant,
                    &core::array::from_fn(|i| words[2 * STATE_WORDS + i].clone()),
                )?;
                let transition = MapTransition {
                    statement: &statement,
                    predecessor: MapState {
                        state: &before,
                        lineage: &previous,
                    },
                    successor: MapState {
                        state: &after,
                        lineage: &successor,
                    },
                };
                if self.variant == Variant::ArchiveReceive {
                    administrative::archive(&mut uint, &mut region, &transition)?;
                } else {
                    administrative::monetary(&mut uint, &mut sponge, &mut region, &transition)?;
                }
                if sponge.lane().rows_used() != hash_rows {
                    return Err(Error::Synthesis);
                }
                Ok(statement.digest().clone())
            },
        )?;
        layouter.constrain_instance(digest.cell(), config.public, 0)
    }
}
