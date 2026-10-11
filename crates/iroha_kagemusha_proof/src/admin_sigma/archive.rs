//! `ArchiveSent`'s fixed state-effect sigma, shared by both Credited evidence forms.

use super::*;

/// Complete G1 openings and the exact `ArchiveSent` statement.
///
/// Native Advance authenticates removal from the committed pending map. A binds
/// the retained Request/Payment/Credited originals, verifies their evidence and
/// constrains the adjusted lineage removal or no-op. This witness has no evidence
/// verdict and does not authorize deleting Payment bytes or releasing value.
#[derive(Clone, Copy, Debug)]
pub struct ArchiveWitness {
    /// Original committed state; `ArchiveSent` may start from an unfolded head.
    pub predecessor: StateWitness,
    /// Successor opening with its carried committed pending root.
    pub successor: StateWitness,
    /// Exact 26-field statement, including credit and Credited digests.
    pub statement: [Fp; 26],
}

/// One fixed k12 sigma source for selector `(ArchiveSent, 0)`.
/// Both evidence forms use this same key; their authentication belongs to A.
#[derive(Clone, Copy, Debug)]
pub struct ArchiveCircuit {
    witness: ArchiveWitness,
    known: bool,
}
impl ArchiveCircuit {
    /// Carry original openings without accepting evidence or authorizing cleanup.
    #[must_use]
    pub const fn new(witness: &ArchiveWitness) -> Self {
        Self {
            witness: *witness,
            known: true,
        }
    }

    /// One bounded digest derived from the complete statement preimage.
    #[must_use]
    pub fn instances(&self) -> [Vec<Fp>; 1] {
        [vec![hash_with_domain(
            STATEMENT_DOMAIN,
            &self.witness.statement,
        )]]
    }

    /// Exact instance membership of the installed PIPA-R profile.
    #[must_use]
    pub const fn instance_types() -> [InstanceType; 1] {
        [InstanceType::Bounded]
    }
}
impl Circuit<Fp> for ArchiveCircuit {
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
        load::Transition {
            predecessor: &self.witness.predecessor,
            successor: &self.witness.successor,
            statement: &self.witness.statement,
            // Both A variants have identical tag5 sigma statement rules. This
            // fixed representative chooses no evidence form or validity result.
            variant: Variant::ArchiveReceive,
            known: self.known,
        }
        .synthesize(config, layouter)
    }
}
