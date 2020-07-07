//! Iroha is a quite dynamic system so many events can happen.
//! This module contains descriptions of such an events and
//! utilitary Iroha Special Instructions to work with them.

/// Iroha Special Instructions module provides `EventInstruction` enum with all legal types of
/// events related instructions as variants, implementations of generic Iroha Special Instructions
/// and the `From/Into` implementations to convert `EventInstruction` variants into generic ISI.
pub mod isi {
    use crate::prelude::*;
    use iroha_derive::*;
    use parity_scale_codec::{Decode, Encode};

    type Trigger = IrohaQuery;

    /// Instructions related to different type of Iroha events.
    /// Some of them are time based triggers, another watch the Blockchain and others
    /// check the World State View.
    #[derive(Clone, Debug, Io, Encode, Decode)]
    pub enum EventInstruction {
        /// This variant of Iroha Special Instruction will execute instruction when new Block
        /// will be created.
        OnBlockCreated(Box<Instruction>),
        /// This variant of Iroha Special Instruction will execute instruction when Blockchain
        /// will reach predefined height.
        OnBlockchainHeight(u64, Box<Instruction>),
        /// This variant of Iroha Special Instruction will execute instruction when World State
        /// View change will be detected by `Trigger`.
        OnWorldStateViewChange(Trigger, Box<Instruction>),
        /// This variant of Iroha Special Instruction will execute instruction regulary.
        OnTimestamp(u128, Box<Instruction>),
    }
}
