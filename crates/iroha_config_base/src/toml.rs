//! TOML-specific tools.
//!
//! While it is definitely possible to support other formats than TOML, since there is no
//! need for this for now, TOML support is integrated in a non-generic way.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

use error_stack::ResultExt;
use serde::Serialize;
use thiserror::Error;
use toml::Table;

use crate::ParameterId;

/// A source of configuration in TOML format
#[derive(Debug, Clone)]
pub struct TomlSource {
    path: PathBuf,
    table: Table,
}

/// Error of [`TomlSource::from_file`]
#[derive(Error, Debug, Copy, Clone)]
#[allow(missing_docs)]
pub enum FromFileError {
    #[error("File system error")]
    Read,
    #[error("Error while deserializing file contents as TOML")]
    Parse,
}

impl TomlSource {
    /// Constructor
    pub fn new(path: PathBuf, table: Table) -> Self {
        Self { path, table }
    }

    /// Read from a file
    ///
    /// # Errors
    /// If a file system or a TOML parsing error occurs.
    pub fn from_file<P: AsRef<Path>>(path: P) -> error_stack::Result<Self, FromFileError> {
        let path = path.as_ref().to_path_buf();

        log::trace!("reading TOML source: `{}`", path.display());

        let mut raw_string = String::new();
        File::open(&path)
            .change_context(FromFileError::Read)?
            .read_to_string(&mut raw_string)
            .change_context(FromFileError::Read)?;

        let table = raw_string
            .parse::<Table>()
            .change_context(FromFileError::Parse)?;

        Ok(TomlSource::new(path, table))
    }

    /// Primarily for testing purposes: creates a source which will contain debug information
    /// about where this source was defined.
    #[track_caller]
    pub fn inline(table: Table) -> Self {
        Self::new(
            PathBuf::from(format!("inline:{}", std::panic::Location::caller())),
            table,
        )
    }

    /// Get an exclusive borrow of the TOML table inside
    pub fn table_mut(&mut self) -> &mut Table {
        &mut self.table
    }

    /// Fetch a value by parameter path
    // FIXME: not optimal code
    // TODO: implement via `Index` trait?
    pub fn fetch(&self, path: &ParameterId) -> Option<toml::Value> {
        enum TableOrValue<'a> {
            Table(&'a Table),
            Value(&'a toml::Value),
        }

        let mut value = TableOrValue::Table(&self.table);

        for segment in &path.segments {
            let table = match value {
                TableOrValue::Table(table) | TableOrValue::Value(toml::Value::Table(table)) => {
                    table
                }
                _ => return None,
            };
            value = TableOrValue::Value(table.get(segment)?);
        }

        // FIXME: cloning
        match value {
            TableOrValue::Table(table) => Some(toml::Value::Table(table.clone())),
            TableOrValue::Value(value) => Some(value.clone()),
        }
    }

    /// Get the file path of the source
    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    // FIXME: false-positive
    //        https://github.com/rust-lang/rust/issues/44752#issuecomment-1712086069
    #[allow(single_use_lifetimes)]
    pub(crate) fn find_unknown<'a>(
        &self,
        known: impl Iterator<Item = &'a ParameterId>,
    ) -> BTreeSet<ParameterId> {
        find_unknown_parameters(&self.table, &known.into())
    }
}

#[derive(Default)]
struct ParamTree<'a>(BTreeMap<&'a str, ParamTree<'a>>);

impl std::fmt::Debug for ParamTree<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl<'a, T> From<T> for ParamTree<'a>
where
    T: Iterator<Item = &'a ParameterId>,
{
    fn from(value: T) -> Self {
        let mut tree = Self(<_>::default());
        for path in value {
            let mut tree_tmp = &mut tree;
            for segment in &path.segments {
                tree_tmp = tree_tmp.0.entry(segment).or_default();
            }
        }
        tree
    }
}

fn find_unknown_parameters(table: &toml::Table, known: &ParamTree) -> BTreeSet<ParameterId> {
    #[derive(Default)]
    struct Traverse<'a> {
        current_path: Vec<&'a str>,
        unknown: BTreeSet<ParameterId>,
    }

    impl<'a> Traverse<'a> {
        fn run(mut self, table: &'a toml::Table, known: &ParamTree) -> Self {
            for (key, value) in table {
                if let Some(known) = known.0.get(key.as_str()) {
                    // we are in the "known"
                    if known.0.is_empty() {
                        // we reached the boundary of explicit "known".
                        // everything below is implied to be known
                    } else if let toml::Value::Table(nested) = value {
                        self.current_path.push(key.as_str());
                        self = self.run(nested, known);
                        self.current_path.pop();
                    }
                } else {
                    // we are in the "unknown"
                    let unknown_path = self
                        .current_path
                        .iter()
                        .chain(std::iter::once(&key.as_str()))
                        .into();
                    self.unknown.insert(unknown_path);
                }
            }

            self
        }
    }

    Traverse::default().run(table, known).unknown
}

/// A utility, primarily for testing, to conveniently write content into a [`Table`].
///
/// ```
/// use iroha_config_base::toml::Writer;
/// use toml::Table;
///
/// let mut table = Table::new();
/// Writer::new(&mut table)
///     .write("foo", "some string")
///     .write("bar", "some other string")
///     .write(["baz", "foo", "bar"], 42);
///
/// assert_eq!(
///     table,
///     toml::toml! {
///         foo = "some string"
///         bar = "some other string"
///
///         [baz.foo]
///         bar = 42
///     }
/// );
/// ```
#[derive(Debug)]
pub struct Writer<'a> {
    table: &'a mut Table,
}

impl<'a> Writer<'a> {
    /// Constructor
    pub fn new(table: &'a mut Table) -> Self {
        Self { table }
    }

    /// Write a serializable value by path.
    /// Recursively creates all path segments as tables if they don't exist.
    ///
    /// # Panics
    ///
    /// - If there is existing non-table value along the path
    /// - If value cannot serialize into [`toml::Value`]
    pub fn write<P: WritePath, T: Serialize>(&'a mut self, path: P, value: T) -> &'a mut Self {
        let mut current: Option<(&mut Table, &str)> = None;

        for i in path.path() {
            if let Some((table, key)) = current {
                let table = table
                    .entry(key)
                    .or_insert(toml::Value::Table(<_>::default()))
                    .as_table_mut()
                    .expect("expected a table");
                current = Some((table, i))
            } else {
                // IDK why Rust allows it
                current = Some((self.table, i))
            }
        }

        if let Some((table, key)) = current {
            let value_toml = toml::Value::try_from(value).expect("value should be a valid TOML");
            table.insert(key.to_string(), value_toml);
        }

        self
    }
}

/// Allows polymorphism for a field path in [`Writer::write`]:
///
/// ```
/// use iroha_config_base::toml::Writer;
///
/// let mut table = toml::Table::new();
/// Writer::new(&mut table)
///     // path: <root>.fine
///     .write("fine", 0)
///     // path: <root>.also.fine
///     .write(["also", "fine"], 1);
/// ```
pub trait WritePath {
    /// Provides an iterator over path segments
    fn path(self) -> impl IntoIterator<Item = &'static str>;
}

impl WritePath for &'static str {
    fn path(self) -> impl IntoIterator<Item = &'static str> {
        [self]
    }
}

impl<const N: usize> WritePath for [&'static str; N] {
    fn path(self) -> impl IntoIterator<Item = &'static str> {
        self
    }
}

impl<'a> From<&'a mut Table> for Writer<'a> {
    fn from(value: &'a mut Table) -> Self {
        Self::new(value)
    }
}

/// Extension trait to implement writing with [`Writer`] directly into [`Table`] in a chained manner.
pub trait WriteExt: Sized {
    /// See [`Writer::write`].
    fn write<P: WritePath, T: Serialize>(self, path: P, value: T) -> Self;
}

impl WriteExt for Table {
    fn write<P: WritePath, T: Serialize>(mut self, path: P, value: T) -> Self {
        Writer::new(&mut self).write(path, value);
        self
    }
}

#[cfg(test)]
mod tests {
    use expect_test::expect;
    use toml::toml;

    use super::*;

    #[test]
    fn create_param_tree() {
        let params = [
            ParameterId::from(["a", "b", "c"]),
            ParameterId::from(["a", "b", "d"]),
            ParameterId::from(["b", "a", "c"]),
            ParameterId::from(["foo", "bar"]),
        ];

        let map = ParamTree::from(params.iter());

        expect![[r#"
                {
                    "a": {
                        "b": {
                            "c": {},
                            "d": {},
                        },
                    },
                    "b": {
                        "a": {
                            "c": {},
                        },
                    },
                    "foo": {
                        "bar": {},
                    },
                }"#]]
        .assert_eq(&format!("{map:#?}"));
    }

    #[test]
    fn unknown_params_in_empty_are_empty() {
        let known = [
            ParameterId::from(["foo", "bar"]),
            ParameterId::from(["foo", "baz"]),
        ];
        let known: ParamTree = known.iter().into();
        let table = toml::Table::new();

        let unknown = find_unknown_parameters(&table, &known);

        assert_eq!(unknown, <_>::default());
    }

    #[test]
    fn with_empty_known_finds_root_unknowns() {
        let table = toml! {
            [foo]
            bar = "hey"

            [baz]
            foo = 412
        };

        let unknown = find_unknown_parameters(&table, &<_>::default());

        let expected = [ParameterId::from(["foo"]), ParameterId::from(["baz"])]
            .into_iter()
            .collect();
        assert_eq!(unknown, expected);
    }

    #[test]
    fn unknown_depth_2() {
        let known = [
            ParameterId::from(["foo", "bar"]),
            ParameterId::from(["foo", "baz"]),
        ];
        let known = ParamTree::from(known.iter());
        let table = toml! {
            [foo]
            bar = 42
            baz = "known"
            foo.bar = { unknown = true }
        };

        let unknown = find_unknown_parameters(&table, &known);

        let expected = vec![ParameterId::from(["foo", "foo"])]
            .into_iter()
            .collect();
        assert_eq!(unknown, expected);
    }

    #[test]
    fn nested_into_known_are_ok() {
        let known = [ParameterId::from(["a"])];
        let known = ParamTree::from(known.iter());
        let table = toml! {
            [a]
            b = 4
            c = 12
        };

        let unknown = find_unknown_parameters(&table, &known);

        assert_eq!(unknown, <_>::default());
    }

    #[test]
    fn writing_into_toml_works() {
        #[derive(Serialize)]
        struct Complex {
            foo: bool,
            bar: bool,
        }

        let mut table = Table::new();

        Writer::new(&mut table)
            .write("foo", "test")
            .write(["bar", "foo"], 42)
            .write(
                ["bar", "complex"],
                &Complex {
                    foo: false,
                    bar: true,
                },
            );

        expect![[r#"
            foo = "test"

            [bar]
            foo = 42

            [bar.complex]
            bar = true
            foo = false
        "#]]
        .assert_eq(&toml::to_string_pretty(&table).unwrap());
    }
}
