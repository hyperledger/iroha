//! Crate with iroha telemetry processing

#[cfg(feature = "dev-telemetry")]
pub mod dev;
pub mod futures;
pub mod metrics;
mod retry_period;
pub mod ws;

pub use iroha_config::telemetry::Configuration;
pub use iroha_telemetry_derive::metrics;

pub mod msg {
    //! Messages that can be sent to the telemetry

    /// The message that is sent to the telemetry when the node is initialized
    pub const SYSTEM_CONNECTED: &str = "system.connected";
}
