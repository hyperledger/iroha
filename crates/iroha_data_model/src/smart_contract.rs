//! This module contains data and structures related only to smart contract execution

pub mod payloads {
    //! Contexts with function arguments for different entrypoints

    use parity_scale_codec::{Decode, Encode};

    use crate::{block::BlockHeader, prelude::*};

    /// Context for smart contract entrypoint
    #[derive(Debug, Clone, Encode, Decode)]
    pub struct SmartContractContext {
        /// Account that submitted the transaction containing the smart contract
        pub authority: AccountId,
        /// Block currently being processed
        pub curr_block: BlockHeader,
    }

    /// Context for trigger entrypoint
    #[derive(Debug, Clone, Encode, Decode)]
    pub struct TriggerContext {
        /// Id of this trigger
        pub id: TriggerId,
        /// Account that registered the trigger
        pub authority: AccountId,
        /// Block currently being processed
        pub curr_block: BlockHeader,
        /// Event which triggered the execution
        pub event: EventBox,
    }

    /// Context for migrate entrypoint
    #[derive(Debug, Clone, Encode, Decode)]
    pub struct ExecutorContext {
        /// Account that is executing the operation
        pub authority: AccountId,
        /// Block currently being processed (or latest block hash for queries)
        pub curr_block: BlockHeader,
    }

    /// Generic payload for `validate_*()` entrypoints of executor.
    #[derive(Debug, Clone, Encode, Decode)]
    pub struct Validate<T> {
        /// Context of the executor
        pub context: ExecutorContext,
        /// Operation to be validated
        pub target: T,
    }
}
