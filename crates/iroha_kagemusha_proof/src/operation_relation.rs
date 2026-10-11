//! In-circuit state openings and operation effects for the lineage aggregator.
//!
//! These constraints use the same 33-field core, eight-field rest and
//! 26-element statements as G1 and the step proofs. They are composed with
//! the hard Q/predecessor verifiers, authenticated signature leaves and
//! obligation folds in A; a state opening alone is not an authorized step.
//!
//! TODO: compose every operation, its signature/object bindings and its
//! exact map transitions before exposing complete lineage proving.

pub mod administrative;
/// Total incoming statement decoding and soft semantic predicates.
pub mod incoming_statement;
pub mod map_effects;
pub mod objects;
pub mod quota_refresh;
pub mod refresh;
pub mod state;
pub mod statement;
