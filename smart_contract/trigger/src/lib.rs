//! Iroha Trigger Rust SDK
#![no_std]
#![allow(unsafe_code)]

#[cfg(not(test))]
use data_model::smart_contract::payloads;
pub use iroha_smart_contract as smart_contract;
pub use iroha_smart_contract_utils::debug;
#[cfg(not(test))]
use iroha_smart_contract_utils::decode_with_length_prefix_from_raw;
pub use iroha_trigger_derive::main;
pub use smart_contract::data_model;

pub mod log {
    //! WASM logging utilities
    pub use iroha_smart_contract_utils::{debug, error, event, info, log::*, trace, warn};
}

#[cfg(not(test))]
mod host {
    #[link(wasm_import_module = "iroha")]
    extern "C" {
        /// Get payload for trigger `main()` entrypoint.
        ///
        /// # Warning
        ///
        /// This function does transfer ownership of the result to the caller
        pub(super) fn get_trigger_payload() -> *const u8;
    }
}

/// Get payload for trigger `main()` entrypoint.
#[cfg(not(test))]
pub fn get_trigger_payload() -> payloads::Trigger {
    // Safety: ownership of the returned result is transferred into `_decode_from_raw`
    unsafe { decode_with_length_prefix_from_raw(host::get_trigger_payload()) }
}

pub mod prelude {
    //! Common imports used by triggers

    pub use iroha_smart_contract::{data_model::prelude::*, prelude::*};
    pub use iroha_smart_contract_utils::debug::DebugUnwrapExt;
    pub use iroha_trigger_derive::main;
}
