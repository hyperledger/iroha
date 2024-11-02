//! Iroha Trigger Rust SDK
#![no_std]
#![allow(unsafe_code)]

pub use iroha_smart_contract as smart_contract;
pub use iroha_smart_contract_utils::{dbg, dbg_panic, DebugExpectExt, DebugUnwrapExt};
pub use iroha_trigger_derive::main;
pub use smart_contract::{data_model, Iroha};

#[doc(hidden)]
pub mod utils {
    //! Crate with utilities

    pub use iroha_smart_contract_utils::register_getrandom_err_callback;

    /// Get context for smart contract `main()` entrypoint.
    ///
    /// # Safety
    ///
    /// It's safe to call this function as long as it's safe to construct, from the given
    /// pointer, byte array of prefix length and `Box<[u8]>` containing the encoded object
    #[doc(hidden)]
    #[cfg(not(test))]
    pub unsafe fn __decode_trigger_context(
        context: *const u8,
    ) -> crate::data_model::smart_contract::payloads::TriggerContext {
        iroha_smart_contract_utils::decode_with_length_prefix_from_raw(context)
    }
}

pub mod log {
    //! WASM logging utilities
    pub use iroha_smart_contract_utils::{debug, error, event, info, trace, warn};
}

pub mod prelude {
    //! Common imports used by triggers
    pub use crate::{
        data_model::{prelude::*, smart_contract::payloads::TriggerContext as Context},
        dbg, dbg_panic, DebugExpectExt, DebugUnwrapExt, Iroha,
    };
}
