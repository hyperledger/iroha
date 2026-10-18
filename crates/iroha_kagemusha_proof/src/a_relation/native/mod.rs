//! Production native assembly of complete fixed operation stage relations.
//!
//! Installation owns artifact authentication and canonical G1 conversion. The
//! relation owners consume typed inputs and retain every proof obligation.
//! Archive pins the shared complete owner source and full envelope domains, with
//! one-key original import and exact source-bound A/W checkpoint restoration.
//! Every family's session can be detached into move-only retained state and
//! resumed only on the exact prover instance that prepared it.
//! TODO: qualify both complete Archive chains and final Omega before wallet
//! installation. No duplicate Archive producer is retained.

pub mod artifact;

pub mod archive;

mod identity;
mod proving;
mod support;

pub mod bootstrap;
pub mod consuming;
pub mod load;
pub mod receive;
pub mod refresh;
pub mod send;
