#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(
    clippy::use_self,
    clippy::implicit_return,
    clippy::must_use_candidate,
    clippy::enum_glob_use,
    clippy::wildcard_imports
)]
pub mod client;
pub mod config;
mod http_client;
