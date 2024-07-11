//! Configuration utils related to Logger specifically.

use std::{
    fmt::{Debug, Display},
    str::FromStr,
};

pub use iroha_data_model::Level;
use serde_with::{DeserializeFromStr, SerializeDisplay};
use tracing_subscriber::filter::Directive;

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

/// List of directives
#[derive(Clone, DeserializeFromStr, SerializeDisplay, PartialEq, Eq)]
pub struct Directives(Vec<Directive>);

impl FromStr for Directives {
    type Err = tracing_subscriber::filter::ParseError;

    fn from_str(dirs: &str) -> std::result::Result<Self, Self::Err> {
        if dirs.is_empty() {
            return Ok(Self(Vec::new()));
        }
        let directives = dirs
            .split(',')
            .filter(|s| !s.is_empty())
            .map(Directive::from_str)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(Self(directives))
    }
}

impl Display for Directives {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut directives_iter = self.0.iter();
        if let Some(directive) = directives_iter.next() {
            write!(f, "{directive}")?;
        }
        for directive in directives_iter {
            write!(f, ",{directive}")?;
        }
        Ok(())
    }
}

impl Debug for Directives {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self, f)
    }
}

impl From<Level> for Directives {
    fn from(level: Level) -> Self {
        Directives(Vec::from([into_tracing_level(level).into()]))
    }
}

impl Default for Directives {
    fn default() -> Self {
        Self::from(Level::INFO)
    }
}

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
