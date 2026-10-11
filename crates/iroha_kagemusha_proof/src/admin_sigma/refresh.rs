//! Single-source `RefreshPolicy` sigma with a constrained five-kind update selector.
//!
//! Update projections are private witnesses. Native preparation and A must bind
//! them to the actual signed object; they grant no authentication or map authority.
//! The fixed k12 source fits the measured 2,499-row maximum advice lane.
//! All five kinds use one original key; no runtime shape selection is provided.

use super::*;
use crate::operation_relation::{
    map_effects::MapState,
    refresh::selected::{SelectedRefreshTransition, UPDATE_FIELDS, constrain_selected},
    statement::RefreshStatementCells,
};

/// Fixed k12 domain shared by every `RefreshPolicy` update kind.
/// The source uses the existing administrative sigma descriptor class.
pub const REFRESH_K: u32 = BOOTSTRAP_K;

/// The five canonical update kinds; the value enters the circuit as advice only.
/// It never selects a different Rust synthesis branch, descriptor or proving key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RefreshKind {
    /// Same-incarnation credential renewal.
    Credential = 1,
    /// Newer scheme policy and its permitted controls intersection.
    SchemePolicy = 2,
    /// Newer blacklist and its separately authenticated history insertion.
    Blacklist = 3,
    /// Newer quota share and its separately authenticated usage-array rebuild.
    QuotaShare = 4,
    /// A different time anchor for the same wallet.
    TimeAnchor = 5,
}

/// Canonical fixed-width projection of one update, authenticated separately by A.
/// Every unused field must be zero in the circuit. Integer fields remain raw Fp
/// witnesses so range violations cannot disappear through host-side truncation.
#[derive(Clone, Copy, Debug)]
pub struct RefreshUpdateWitness {
    /// Typed kind, constrained equal to the statement's update kind.
    pub kind: RefreshKind,
    /// Original signed object's digest, nonzero for every kind.
    pub digest: Fp,
    /// Scheme for all kinds except Credential, where both limbs are zero.
    pub scheme: [Fp; 2],
    /// Asset for `SchemePolicy`/`QuotaShare`, zero otherwise.
    pub asset: [Fp; 2],
    /// Wallet for QuotaShare/TimeAnchor, zero otherwise.
    pub wallet: [Fp; 2],
    /// Policy epoch, list version or share id; zero for Credential/TimeAnchor.
    pub counter: Fp,
    /// Signed issue/issuer time; zero for `SchemePolicy`, which preserves the floor.
    pub issued_at_ms: Fp,
    /// Credential lease or quota expiry, zero otherwise.
    pub expires_at_ms: Fp,
    /// Blacklist entries root or quota windows root, zero otherwise.
    pub root: Fp,
    /// Scheme policy's three-bit controls, zero otherwise.
    pub controls: Fp,
    /// Scheme policy's optional fee-schedule digest, zero otherwise.
    pub fee_schedule: Fp,
}
impl RefreshUpdateWitness {
    fn fields(&self) -> [Fp; UPDATE_FIELDS] {
        [
            self.digest,
            self.scheme[0],
            self.scheme[1],
            self.asset[0],
            self.asset[1],
            self.wallet[0],
            self.wallet[1],
            self.counter,
            self.issued_at_ms,
            self.expires_at_ms,
            self.root,
            self.controls,
            self.fee_schedule,
        ]
    }
}

/// Complete G1 openings, exact statement and the update's canonical projection.
#[derive(Clone, Copy, Debug)]
pub struct RefreshWitness {
    /// Original committed state; this operation can start from an unfolded head.
    pub predecessor: StateWitness,
    /// Successor after exactly one selected refresh effect.
    pub successor: StateWitness,
    /// Exact 26-field tag7 statement with update kind, digest and accepted floor.
    pub statement: [Fp; 26],
    /// Typed fixed-layout update projection, not an issuer-authentication verdict.
    pub update: RefreshUpdateWitness,
}

/// One fixed circuit for all five kinds under selector `(RefreshPolicy, 0)`.
/// A still owns signatures, immutable renewal identity and exact map/rebuild checks.
#[derive(Clone, Copy, Debug)]
pub struct RefreshCircuit {
    witness: RefreshWitness,
    known: bool,
}
impl RefreshCircuit {
    /// Carry original witnesses without authenticating an update or accepting a step.
    #[must_use]
    pub const fn new(witness: &RefreshWitness) -> Self {
        Self {
            witness: *witness,
            known: true,
        }
    }

    /// The one bounded statement digest, always derived from the original fields.
    #[must_use]
    pub fn instances(&self) -> [Vec<Fp>; 1] {
        [vec![hash_with_domain(
            STATEMENT_DOMAIN,
            &self.witness.statement,
        )]]
    }

    /// Exact homogeneous PIPA-R instance membership.
    #[must_use]
    pub const fn instance_types() -> [InstanceType; 1] {
        [InstanceType::Bounded]
    }
}
impl Circuit<Fp> for RefreshCircuit {
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

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let mut glue = GlueChip::starting_at(config.glue, load::BASE_HASH_ROWS);
        let mut range = RunningSumChip::new(config.range);
        let mut sponge = SpongeChip::new(config.sponge);
        range.load_table(&mut layouter)?;
        let digest = layouter.assign_region(
            || "single-source RefreshPolicy sigma",
            |mut region| {
                let before = &self.witness.predecessor;
                let after = &self.witness.successor;
                let projection = self.witness.update.fields();
                let kind = Fp::from(self.witness.update.kind as u64);
                let values = before
                    .core
                    .iter()
                    .chain(&before.rest)
                    .chain(&before.lineage)
                    .chain(&after.core)
                    .chain(&after.rest)
                    .chain(&after.lineage)
                    .chain(&self.witness.statement)
                    .chain(std::iter::once(&kind))
                    .chain(&projection)
                    .map(|value| {
                        if self.known {
                            Value::known(*value)
                        } else {
                            Value::unknown()
                        }
                    })
                    .collect::<Vec<_>>();
                let words = glue.witnesses(&mut region, &values)?;
                let mut uint = UintChip::new(&mut glue, &mut range);
                let (before, previous) = load::state(
                    &mut uint,
                    &mut sponge,
                    &mut region,
                    &words[..load::STATE_WORDS],
                )?;
                let (after, successor) = load::state(
                    &mut uint,
                    &mut sponge,
                    &mut region,
                    &words[load::STATE_WORDS..2 * load::STATE_WORDS],
                )?;
                let offset = 2 * load::STATE_WORDS;
                let statement = RefreshStatementCells::constrain(
                    &mut uint,
                    &mut sponge,
                    &mut region,
                    &core::array::from_fn(|i| words[offset + i].clone()),
                )?;
                GlueChip::assert_equal(&mut region, &words[offset + 26], &statement.fields()[17])?;
                constrain_selected(
                    &mut uint,
                    &mut region,
                    &SelectedRefreshTransition {
                        statement: &statement,
                        predecessor: MapState {
                            state: &before,
                            lineage: &previous,
                        },
                        successor: MapState {
                            state: &after,
                            lineage: &successor,
                        },
                    },
                    &core::array::from_fn(|i| words[offset + 27 + i].clone()),
                )?;
                if sponge.lane().rows_used() != load::BASE_HASH_ROWS {
                    return Err(Error::Synthesis);
                }
                Ok(statement.digest().clone())
            },
        )?;
        layouter.constrain_instance(digest.cell(), config.public, 0)
    }
}
