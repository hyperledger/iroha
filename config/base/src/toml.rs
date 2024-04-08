use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};

use crate::ParameterId;

#[derive(Debug, Clone)]
pub struct TomlSource {
    path: PathBuf,
    table: toml::Table,
}

impl TomlSource {
    pub fn new(path: PathBuf, table: toml::Table) -> Self {
        Self { path, table }
    }

    pub fn fetch(&self, path: &ParameterId) -> Option<toml::Value> {
        enum TableOrValue<'a> {
            Table(&'a toml::Table),
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

    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    #[allow(single_use_lifetimes)] // FIXME: when I remove `'a`, it cannot compile
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

#[cfg(test)]
mod tests {
    use expect_test::expect;
    use toml::toml;

    use super::*;

    #[test]
    fn create_param_tree() {
        let params = vec![
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
        let known = vec![
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

        let expected = vec![ParameterId::from(["foo"]), ParameterId::from(["baz"])]
            .into_iter()
            .collect();
        assert_eq!(unknown, expected);
    }

    #[test]
    fn unknown_depth_2() {
        let known = vec![
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
        let known = vec![ParameterId::from(["a"])];
        let known = ParamTree::from(known.iter());
        let table = toml! {
            [a]
            b = 4
            c = 12
        };

        let unknown = find_unknown_parameters(&table, &known);

        assert_eq!(unknown, <_>::default());
    }
}
