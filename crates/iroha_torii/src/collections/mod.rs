//! One query engine behind every Torii collection endpoint.
//!
//! The wire contract is `specs/torii/collection_queries.md`; the request and page
//! types are [`iroha_torii_shared::list_query`]. Each collection declares its
//! row fields in [`specs`]; row producers live next to the state accessors in
//! `routing::collection_sources`. Execution filters rows, skips everything up to
//! the cursor's keyset position and keeps only the best `limit + 1` rows, so a
//! page costs one pass over the candidates and `O(limit)` memory whatever its
//! depth.
mod cursor;
mod engine;
pub mod memory;
pub mod specs;

pub use engine::{Limits, Prepared, RowPage, prepare};
pub use specs::CollectionSpec;

/// Collections whose reads accept `aggregate` (advertised by `/v1/node/capabilities`).
pub fn aggregate_collections() -> impl Iterator<Item = &'static str> {
    specs::ALL
        .into_iter()
        .filter(|spec| spec.positioned == 0)
        .map(|spec| spec.id)
}

/// Collections exported by query projection archives.
pub const PROJECTION_EXPORT_COLLECTIONS: [&str; 5] = [
    "accounts",
    "account_assets",
    "asset_holders",
    "asset_definitions",
    "domains",
];

use iroha_torii_shared::{ErrorDetails, ErrorEnvelope, list_query::ListQueryError};
use std::fmt;

/// A collection query that cannot be executed as written (HTTP 400).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionError {
    /// Stable error code such as `invalid_filter`.
    pub code: &'static str,
    /// Human-readable description.
    pub message: Box<str>,
    /// The request control at fault (`filter`, `sort`, …).
    pub control: &'static str,
    /// The offending data field or value, when one is known.
    pub actual: Option<String>,
    /// The accepted fields or values, when that helps.
    pub expected: Option<String>,
    /// A suggested fix.
    pub hint: Option<String>,
}

impl CollectionError {
    pub(crate) fn new(
        code: &'static str,
        control: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            message: message.into().into_boxed_str(),
            control,
            actual: None,
            expected: None,
            hint: None,
        }
    }

    pub(crate) fn with_actual(mut self, actual: impl Into<String>) -> Self {
        self.actual = Some(actual.into());
        self
    }

    pub(crate) fn with_expected(mut self, expected: impl Into<String>) -> Self {
        self.expected = Some(expected.into());
        self
    }

    pub(crate) fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    /// The error envelope returned to clients.
    pub fn envelope(&self) -> ErrorEnvelope {
        ErrorEnvelope::new(self.code, self.message.to_string()).with_details(ErrorDetails {
            field: Some(self.control.to_owned()),
            actual: self.actual.clone(),
            expected: self.expected.clone(),
            hint: self.hint.clone(),
            ..ErrorDetails::default()
        })
    }
}

impl From<ListQueryError> for CollectionError {
    fn from(err: ListQueryError) -> Self {
        let message = err.to_string();
        Self::new(err.code(), err.parameter, message)
    }
}

impl fmt::Display for CollectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CollectionError {}

impl From<CollectionError> for crate::Error {
    fn from(err: CollectionError) -> Self {
        Self::CollectionQuery(Box::new(err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_collection_error_preserves_the_response_details() {
        let error = CollectionError::new("invalid_filter", "filter", "unknown field")
            .with_actual("ownd_by")
            .with_expected("owned_by")
            .with_hint("use the canonical field name");
        let envelope = error.envelope();
        assert_eq!(error.to_string(), "unknown field");
        assert_eq!(envelope.code, "invalid_filter");
        assert_eq!(envelope.message, "unknown field");
        let details = envelope.details.expect("collection error details");
        assert_eq!(details.field.as_deref(), Some("filter"));
        assert_eq!(details.actual.as_deref(), Some("ownd_by"));
        assert_eq!(details.expected.as_deref(), Some("owned_by"));
        assert_eq!(
            details.hint.as_deref(),
            Some("use the canonical field name")
        );
    }

    #[test]
    fn capability_lists_name_real_collections() {
        let aggregates: Vec<_> = aggregate_collections().collect();
        assert!(aggregates.contains(&"asset_holders"));
        assert!(
            !aggregates.contains(&"account_transactions"),
            "history has no aggregates"
        );
        for id in PROJECTION_EXPORT_COLLECTIONS {
            assert!(specs::ALL.iter().any(|spec| spec.id == id), "{id}");
        }
    }
}
