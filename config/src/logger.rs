//! Configuration utils related to Logger specifically.

pub use iroha_data_model::Level;
use serde_with::{DeserializeFromStr, SerializeDisplay};

/// Convert [`Level`] into [`tracing::Level`]
pub fn into_tracing_level(level: Level) -> tracing::Level {
    match level {
        Level::TRACE => tracing::Level::TRACE,
        Level::DEBUG => tracing::Level::DEBUG,
        Level::INFO => tracing::Level::INFO,
        Level::WARN => tracing::Level::WARN,
        Level::ERROR => tracing::Level::ERROR,
    }
}

/// Reflects formatters in [`tracing_subscriber::fmt::format`]
#[derive(
    Debug,
    Copy,
    Clone,
    Eq,
    PartialEq,
    strum::Display,
    strum::EnumString,
    Default,
    SerializeDisplay,
    DeserializeFromStr,
)]
#[strum(serialize_all = "snake_case")]
pub enum Format {
    /// See [`tracing_subscriber::fmt::format::Full`]
    #[default]
    Full,
    /// See [`tracing_subscriber::fmt::format::Compact`]
    Compact,
    /// See [`tracing_subscriber::fmt::format::Pretty`]
    Pretty,
    /// See [`tracing_subscriber::fmt::format::Json`]
    Json,
}

#[cfg(test)]
pub mod tests {
    use crate::logger::Format;

    #[test]
    fn serialize_pretty_format_in_lowercase() {
        let value = Format::Pretty;
        let actual = serde_json::to_string(&value).unwrap();
        assert_eq!("\"pretty\"", actual);
    }
}
