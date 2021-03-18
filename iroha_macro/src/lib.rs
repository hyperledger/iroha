#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(
    clippy::doc_markdown,
    clippy::use_self,
    clippy::implicit_return,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::enum_glob_use,
    clippy::wildcard_imports
)]
pub mod error {
    pub use iroha_error::*;
}

pub trait Io: parity_scale_codec::Encode + parity_scale_codec::Decode {}
pub trait IntoContract {}
pub trait IntoQuery {}
