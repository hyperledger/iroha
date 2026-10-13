//! Concurrently readable B+trees and epoch-reclaimed cells used by Iroha.
//!
//! Synchronous writers publish new generations while existing readers retain
//! immutable snapshots. The B+tree supports admitted allocation ownership and
//! explicit publication phases; EBR cells retain charges through reclamation.
//!
//! The default features enable `ebr` and `maps`. `skinny` exercises the same
//! B+tree engine with a smaller fanout for structural testing.

#![deny(warnings)]
#![warn(unused_extern_crates)]
#![warn(missing_docs)]
#![allow(clippy::needless_lifetimes)]
#![allow(clippy::type_complexity)]

#[cfg(feature = "ebr")]
pub mod ebrcell;
#[cfg(feature = "ebr")]
pub use ebrcell::EbrCell;

#[cfg(feature = "maps")]
pub mod bptree;
/// B+tree and linear-cell primitives for coordinated storage ownership.
#[cfg(feature = "maps")]
pub mod internals;
#[cfg(feature = "maps")]
mod utils;

#[cfg(all(test, feature = "maps"))]
mod lc_tests;

#[cfg(all(test, any(feature = "maps", feature = "ebr")))]
mod release_test_support;
