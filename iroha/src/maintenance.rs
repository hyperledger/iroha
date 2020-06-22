//! `Maintenance` module provides structures and implementation blocks related to `Iroha`
//! maintenance functions like Healthcheck, Monitoring, etc.

use iroha_derive::Io;
use parity_scale_codec::{Decode, Encode};

/// `Health` enumerates different variants of Iroha `Peer` states.
/// Each variant can provide additional information if needed.
#[derive(Clone, Debug, Io, Encode, Decode)]
pub enum Health {
    /// `Healthy` variant means that `Peer` has finished initial setup.
    Healthy,
    /// `Ready` variant means that `Peer` bootstrapping completed.
    Ready,
}
