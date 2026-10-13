//! RAII wrappers and parsers for secret-bearing TOML.

use color_eyre::eyre::{Result, eyre};
use std::ops::{Deref, DerefMut};
use zeroize::Zeroize as _;

/// Parse a TOML table without returning the parser's source-bearing error.
///
/// `toml::de::Error` retains the complete input and renders source lines. Runtime configuration
/// commonly contains private keys or passwords, so preserve only the byte offset before dropping
/// that error and return a deliberately generic diagnostic.
///
/// # Errors
/// Returns a source-free diagnostic when the input is not a valid TOML table.
pub fn parse_table(input: &str, description: &str) -> Result<toml::Table> {
    input.parse::<toml::Table>().map_err(|mut error| {
        let offset = error.span().map(|span| span.start);
        error.set_input(None);
        drop(error);
        offset.map_or_else(
            || eyre!("{description} is not valid TOML"),
            |offset| eyre!("{description} is not valid TOML near byte {offset}"),
        )
    })
}

/// A TOML table whose string storage is erased before deallocation.
#[derive(Default)]
pub struct Table(toml::Table);

impl Table {
    /// Wrap a table before retaining or transforming secret-bearing fields.
    pub const fn new(table: toml::Table) -> Self {
        Self(table)
    }
}

impl Deref for Table {
    type Target = toml::Table;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Table {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for Table {
    fn drop(&mut self) {
        zeroize_table(&mut self.0);
    }
}

/// A TOML value whose nested string storage is erased before deallocation.
pub struct Value(toml::Value);

impl Value {
    /// Wrap a value before adding or serializing secret fields.
    pub const fn new(value: toml::Value) -> Self {
        Self(value)
    }
}

impl Deref for Value {
    type Target = toml::Value;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Value {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for Value {
    fn drop(&mut self) {
        zeroize_value(&mut self.0);
    }
}

/// Insert a TOML value and erase any replaced value before it is released.
pub fn insert(table: &mut toml::Table, key: String, value: toml::Value) {
    if let Some(mut replaced) = table.insert(key, value) {
        zeroize_value(&mut replaced);
    }
}

/// Remove a TOML value and erase it before it is released.
pub fn remove(table: &mut toml::Table, key: &str) {
    if let Some(mut removed) = table.remove(key) {
        zeroize_value(&mut removed);
    }
}

/// Erase every string value recursively before releasing a secret-bearing TOML table.
pub fn zeroize_table(table: &mut toml::Table) {
    table.iter_mut().for_each(|(_, value)| zeroize_value(value));
}

fn zeroize_value(value: &mut toml::Value) {
    match value {
        toml::Value::String(value) => value.zeroize(),
        toml::Value::Array(values) => values.iter_mut().for_each(zeroize_value),
        toml::Value::Table(table) => zeroize_table(table),
        toml::Value::Integer(_)
        | toml::Value::Float(_)
        | toml::Value::Boolean(_)
        | toml::Value::Datetime(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeroize_value_clears_nested_string_storage() {
        let mut nested = toml::Table::new();
        nested.insert(
            "secret".to_owned(),
            toml::Value::String("sensitive".to_owned()),
        );
        let mut value = toml::Value::Array(vec![toml::Value::Table(nested)]);

        zeroize_value(&mut value);

        assert_eq!(value[0]["secret"].as_str(), Some(""));
    }

    #[test]
    fn replacement_and_removal_helpers_leave_only_the_current_value() {
        let mut table = toml::Table::new();
        insert(
            &mut table,
            "secret".to_owned(),
            toml::Value::String("old secret".to_owned()),
        );
        insert(
            &mut table,
            "secret".to_owned(),
            toml::Value::String("new secret".to_owned()),
        );
        assert_eq!(table["secret"].as_str(), Some("new secret"));
        remove(&mut table, "secret");
        assert!(!table.contains_key("secret"));
    }

    #[test]
    fn parser_errors_do_not_echo_secret_input() {
        let secret = "do-not-log-this-private-key";
        let input = format!("private_key = \"{secret}\"\ninvalid = [");

        let error = parse_table(&input, "runtime config").expect_err("malformed TOML");
        let rendered = format!("{error:?}");

        assert!(rendered.contains("runtime config is not valid TOML"));
        assert!(!rendered.contains(secret));
        assert!(!rendered.contains("private_key"));
    }
}
