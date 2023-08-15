//! Iroha Trigger Rust SDK

#![no_std]

pub use iroha_trigger_derive::main;
pub use iroha_wasm::{self, data_model, *};

pub mod prelude {
    //! Common imports used by triggers

    pub use iroha_trigger_derive::main;
    pub use iroha_wasm::{data_model::prelude::*, prelude::*};
}
