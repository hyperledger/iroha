//! This module contains data and structures related only to smart contract execution

pub mod payloads {
    //! Payloads with function arguments for different entrypoints

    use parity_scale_codec::{Decode, Encode};

    use crate::prelude::*;

    /// Payload for smart contract entrypoint
    #[derive(Debug, Clone, Encode, Decode)]
    pub struct SmartContract {
        /// Smart contract owner who submitted transaction with it
        pub owner: AccountId,
    }

    /// Payload for trigger entrypoint
    #[derive(Debug, Clone, Encode, Decode)]
    pub struct Trigger {
        /// Trigger owner who registered the trigger
        pub owner: AccountId,
        /// Event which triggered the execution
        pub event: Event,
    }

    /// Payload for migrate entrypoint
    #[derive(Debug, Clone, Copy, Encode, Decode)]
    pub struct Migrate {
        /// Height of the latest block in the blockchain
        pub block_height: u64,
    }

    /// Generic payload for `validate_*()` entrypoints of executor.
    #[derive(Debug, Clone, Encode, Decode)]
    pub struct Validate<T> {
        /// Authority which executed the operation to be validated
        pub authority: AccountId,
        /// Height of the latest block in the blockchain
        pub block_height: u64,
        /// Operation to be validated
        pub to_validate: T,
    }
}
