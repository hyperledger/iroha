//! Iroha Trigger Rust SDK
#![no_std]
#![allow(unsafe_code)]

pub use iroha_smart_contract as smart_contract;
pub use iroha_smart_contract_utils::debug;
pub use iroha_trigger_derive::main;
pub use smart_contract::{data_model, stub_getrandom};

pub mod log {
    //! WASM logging utilities
    pub use iroha_smart_contract_utils::{debug, error, event, info, log::*, trace, warn};
}

#[cfg(not(test))]
mod host {
    #[link(wasm_import_module = "iroha")]
    extern "C" {
        /// Get context for trigger `main()` entrypoint.
        ///
        /// # Warning
        ///
        /// This function does transfer ownership of the result to the caller
        pub(super) fn get_trigger_context() -> *const u8;
    }
}

/// Get context for trigger `main()` entrypoint.
#[cfg(not(test))]
pub fn get_trigger_context() -> data_model::smart_contract::payloads::TriggerContext {
    // Safety: ownership of the returned result is transferred into `_decode_from_raw`
    unsafe {
        iroha_smart_contract_utils::decode_with_length_prefix_from_raw(host::get_trigger_context())
    }
}

pub mod prelude {
    //! Common imports used by triggers

    pub use iroha_smart_contract::prelude::*;
    pub use iroha_smart_contract_utils::debug::DebugUnwrapExt;
    pub use iroha_trigger_derive::main;

    pub use crate::data_model::smart_contract::payloads::TriggerContext as Context;
}
