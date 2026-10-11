//! A's typed lineage frame and fixed recursive obligation wiring.
//!
//! These components consume constrained operation cells in the same relation.
//! A recursive proof frame alone does not establish an operation transition;
//! the operation, authenticated-map and byte-consumer constraints must compose
//! with it before the resulting circuit can authorize a lineage update.

pub mod archive;
mod binding;
pub mod bootstrap;
pub mod context;
mod frame;
mod incoming_lineage;
pub mod incoming_transport;
pub mod load;
pub mod load_receipt;
pub mod native;
pub mod own;
pub mod receive;
pub mod refresh;
pub mod results;
pub mod schedule;
pub mod send;
pub mod split;
pub mod unload;
pub use incoming_lineage::IncomingLineageCells;
mod proof;
mod signature;

pub use signature::{SignatureProofCells, SignatureQCells, SignatureQContext, bind_signature_q};

pub use binding::{
    AOutputCells, BoundSigmaCells, IncomingVestaCells, SigmaBindingCells, VestaClaimCells,
    bounded_word, lineage_digest,
};
pub use frame::{AFramePlan, LINEAGE_DOMAIN, LINEAGE_FIELDS, LineagePublicCells};
pub use proof::{
    AProofPlan, IncomingOmegaCells, PredecessorCells, ProofMessageCells, QProofPlan,
    SelectedPallasCells, VerifiedQCells, bind_modes, fold_pallas, select_incoming, verify_incoming,
    verify_predecessor, verify_q, verify_sigma,
};

use binding::bind_sigma;
