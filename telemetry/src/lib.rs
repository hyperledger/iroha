//! Crate with iroha telemetry processing

mod config;
#[cfg(feature = "dev-telemetry")]
pub mod dev;
pub mod futures;
mod retry_period;
pub mod ws;

pub use config::Configuration;

pub mod msg {
    //! Messages that can be sent to the telemetry

    /// The message that is sent to the telemetry when the node is initialized
    pub const SYSTEM_CONNECTED: &str = "system.connected";
}
