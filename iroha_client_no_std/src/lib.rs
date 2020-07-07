pub mod client;
pub mod config;
// TODO(vmarkushin): update documentation for the client-side entities (IR-848).
pub mod account;
pub mod asset;
pub mod domain;
pub mod event;
pub mod isi;
pub mod peer;
pub mod permission;
pub mod query;
pub mod tx;

pub mod prelude {
    pub use super::{
        account::*, asset::*, domain::*, event::*, isi::*, peer::*, permission::*, query::*, tx::*,
        Identifiable,
    };
}

/// This trait marks entity that implement it as identifiable with an `Id` type to find them by.
pub trait Identifiable {
    /// Defines the type of entity's identification.
    type Id;
}
