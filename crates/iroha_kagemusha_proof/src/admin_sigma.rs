//! Administrative sigma relations over the exact G1 state and statement.
//!
//! Bootstrap proves the initial zero-value state, empty maps and counters.
//! Load, Unload, Retiring, `ArchiveSent` and the shared five-kind Refresh class
//! prove exact private state effects, checked value arithmetic and
//! statement/head/lineage continuity. A separately authenticates
//! their objects, map updates and predecessor proofs. These leaves are not
//! stand-alone enrollment, monetary authorization or wallet acceptance APIs.

use iroha_pasta::{Fp, poseidon::hash_with_domain};
use iroha_plonk::{
    cs::{Column, ConstraintSystem, Instance, InstanceType},
    frontend::{Circuit, Error, Layouter, SimpleFloorPlanner, Value},
};
use iroha_plonk_gadgets::{
    GlueChip, GlueConfig, LimbBits, Pow5Columns, RoundConstantColumns, RunningSumChip,
    RunningSumConfig, SpongeChip, SpongeConfig, UintChip,
    poseidon::{pow5::ROWS_PER_PERMUTATION, sponge::domain_permutations},
    statement::STATEMENT_DOMAIN,
};
use iroha_plonk_recursion::obligation::ledger::Variant;

use crate::{
    a_relation::LineagePublicCells,
    operation_relation::{administrative, state::StateCells, statement::StatementCells},
    witness::{CORE_DOMAIN, CORE_FIELDS, REST_DOMAIN, REST_FIELDS},
};

/// Original-key import and typed proving owners for the fixed administrative leaves.
pub mod native;

#[path = "admin_sigma/load.rs"]
mod load;
pub use load::{LoadCircuit, LoadWitness, StateWitness};

#[path = "admin_sigma/consuming.rs"]
mod consuming;
pub use consuming::{ConsumingWitness, RetiringCircuit, UnloadCircuit};

#[path = "admin_sigma/archive.rs"]
mod archive;
pub use archive::{ArchiveCircuit, ArchiveWitness};

#[path = "admin_sigma/refresh.rs"]
mod refresh;
pub use refresh::{REFRESH_K, RefreshCircuit, RefreshKind, RefreshUpdateWitness, RefreshWitness};

/// Fixed domain size of the Bootstrap sigma class.
pub const BOOTSTRAP_K: u32 = 12;

// The four glue columns reuse the sponge columns after its complete fixed
// schedule. This boundary does not depend on any witness or hash output.
const HASH_ROWS: usize = (domain_permutations(CORE_FIELDS + 1, true)
    + domain_permutations(REST_FIELDS, true)
    + domain_permutations(26, true))
    * ROWS_PER_PERMUTATION;
const LIMBS: LimbBits = match LimbBits::new(9) {
    Some(bits) => bits,
    None => panic!("constant limb width must be supported"),
};

/// Original G1 state, lineage and statement witness; no host-side validity bit.
#[derive(Clone, Copy, Debug)]
pub struct BootstrapWitness {
    /// Exact 33-field state core.
    pub core: [Fp; CORE_FIELDS],
    /// Exact eight-field state rest.
    pub rest: [Fp; REST_FIELDS],
    /// Exact 18-field public lineage prefix.
    pub lineage: [Fp; 18],
    /// Exact 26-field Bootstrap statement.
    pub statement: [Fp; 26],
}

/// Fixed Bootstrap relation with one bounded public statement digest.
#[derive(Clone, Copy, Debug)]
pub struct BootstrapCircuit {
    witness: BootstrapWitness,
    known: bool,
}

impl BootstrapCircuit {
    /// Carries a witness to be checked by the circuit; performs no acceptance.
    #[must_use]
    pub const fn new(witness: &BootstrapWitness) -> Self {
        Self {
            witness: *witness,
            known: true,
        }
    }

    /// The statement digest, whose preimage and state effects are constrained.
    #[must_use]
    pub fn instances(&self) -> [Vec<Fp>; 1] {
        [vec![hash_with_domain(
            STATEMENT_DOMAIN,
            &self.witness.statement,
        )]]
    }

    /// Exact homogeneous instance membership for PIPA-R key generation.
    #[must_use]
    pub const fn instance_types() -> [InstanceType; 1] {
        [InstanceType::Bounded]
    }
}

/// Shared four-column sponge/glue lane, range lane and public column.
#[derive(Clone, Debug)]
pub struct AdminConfig {
    glue: GlueConfig,
    range: RunningSumConfig,
    sponge: SpongeConfig<Fp>,
    public: Column<Instance>,
}

impl Circuit<Fp> for BootstrapCircuit {
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
        let lane = Pow5Columns::allocate(meta);
        let constants = meta.fixed_column();
        let glue = GlueConfig::configure(
            meta,
            [lane.state[0], lane.state[1], lane.state[2], lane.aux],
            constants,
        );
        let z = meta.advice_column();
        let range = RunningSumConfig::configure(meta, z, LIMBS);
        let rounds = RoundConstantColumns::allocate(meta);
        let sponge = SpongeConfig::configure(
            meta,
            lane,
            rounds,
            &[
                (CORE_DOMAIN, CORE_FIELDS + 1),
                (REST_DOMAIN, REST_FIELDS),
                (STATEMENT_DOMAIN, 26),
            ],
        );
        let public = meta.instance_column(1);
        meta.enable_equality(public);
        AdminConfig {
            glue,
            range,
            sponge,
            public,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let mut glue = GlueChip::starting_at(config.glue, HASH_ROWS);
        let mut range = RunningSumChip::new(config.range);
        let mut sponge = SpongeChip::new(config.sponge);
        range.load_table(&mut layouter)?;
        let digest = layouter.assign_region(
            || "Bootstrap administrative sigma",
            |mut region| {
                let values = self
                    .witness
                    .core
                    .iter()
                    .chain(&self.witness.rest)
                    .chain(&self.witness.lineage)
                    .chain(&self.witness.statement)
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
                let state = StateCells::constrain(
                    &mut uint,
                    &mut sponge,
                    &mut region,
                    &core::array::from_fn(|i| words[i].clone()),
                    &core::array::from_fn(|i| words[CORE_FIELDS + i].clone()),
                )?;
                let lineage = LineagePublicCells::constrain(
                    &mut uint,
                    &mut region,
                    &core::array::from_fn(|i| words[CORE_FIELDS + REST_FIELDS + i].clone()),
                )?;
                let statement = StatementCells::constrain(
                    &mut uint,
                    &mut sponge,
                    &mut region,
                    Variant::Bootstrap,
                    &core::array::from_fn(|i| words[CORE_FIELDS + REST_FIELDS + 18 + i].clone()),
                )?;
                administrative::bootstrap(&mut uint, &mut region, &statement, &state, &lineage)?;
                if sponge.lane().rows_used() != HASH_ROWS {
                    return Err(Error::Synthesis);
                }
                Ok(statement.digest().clone())
            },
        )?;
        layouter.constrain_instance(digest.cell(), config.public, 0)
    }
}
