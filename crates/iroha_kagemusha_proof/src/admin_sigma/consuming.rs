//! Fixed Unload and Retiring leaves over a folded predecessor's adjusted state.

use super::*;

/// State openings and statement for an Unload or Retiring step.
///
/// A must authenticate the predecessor Ω, exact sigma proof, current
/// credential, direct enrollment certificate and this step's receipt.
/// For Unload it also proves the recovery-map insertion. These openings
/// alone do not authorize a monetary operation.
#[derive(Clone, Copy, Debug)]
pub struct ConsumingWitness {
    /// State and adjusted lineage opened by the hard predecessor proof.
    pub predecessor: StateWitness,
    /// State committed after this irreversible step.
    pub successor: StateWitness,
    /// Exact 26-field public statement preimage.
    pub statement: [Fp; 26],
}

macro_rules! consuming_circuit {
    ($name:ident, $variant:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug)]
        pub struct $name {
            witness: ConsumingWitness,
            known: bool,
        }

        impl $name {
            /// Carry the complete witness without accepting the operation.
            #[must_use]
            pub const fn new(witness: &ConsumingWitness) -> Self {
                Self {
                    witness: *witness,
                    known: true,
                }
            }

            /// One bounded statement digest whose preimage is constrained.
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

        impl Circuit<Fp> for $name {
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
                layouter: impl Layouter<Fp>,
            ) -> Result<(), Error> {
                load::Transition {
                    predecessor: &self.witness.predecessor,
                    successor: &self.witness.successor,
                    statement: &self.witness.statement,
                    variant: Variant::$variant,
                    known: self.known,
                }
                .synthesize(config, layouter)
            }
        }
    };
}

consuming_circuit!(
    UnloadCircuit,
    Unload,
    "Unload's fixed k12 leaf: adjusted-balance spend, ordinal, nullifier and exact state effects."
);
consuming_circuit!(
    RetiringCircuit,
    Retiring,
    "Retiring's fixed k12 leaf: one-way lifecycle change and adjusted lineage synchronization."
);
