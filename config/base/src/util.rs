use std::{path::PathBuf, time::Duration};

use drop_bomb::DropBomb;
use error_stack::Report;
use serde::{Deserialize, Serialize};

/// [`Duration`], but can parse a human-readable string.
/// TODO: currently deserializes just as [`Duration`]
#[serde_with::serde_as]
#[derive(Debug, Copy, Clone, Deserialize, Serialize, Ord, PartialOrd, Eq, PartialEq)]
pub struct HumanDuration(#[serde_as(as = "serde_with::DurationMilliSeconds")] pub Duration);

impl HumanDuration {
    /// Get the [`Duration`]
    pub fn get(self) -> Duration {
        self.0
    }
}

impl From<Duration> for HumanDuration {
    fn from(value: Duration) -> Self {
        Self(value)
    }
}

/// Representation of number of bytes, parseable from a human-readable string.
#[derive(Debug, Copy, Clone, Deserialize, Serialize)]
pub struct HumanBytes<T: num_traits::int::PrimInt>(pub T);

impl<T: num_traits::int::PrimInt> HumanBytes<T> {
    /// Get the number of bytes
    pub fn get(self) -> T {
        self.0
    }
}

impl<T: num_traits::int::PrimInt> From<T> for HumanBytes<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

/// A tool to implement "extends" mechanism, i.e. mixins.
///
/// It allows users to provide a path of other files that should be used as
/// a _base_ layer.
///
/// ```toml
/// # contents of this file will be merged into the contents of `base.toml`
/// extends = "./base.toml"
/// ```
///
/// It is possible to specify multiple extensions at once:
///
/// ```toml
/// # read `foo`, then merge `bar`, then merge `baz`, then merge this file's contents
/// extends = ["foo", "bar", "baz"]
/// ```
///
/// From the developer side, it should be used as a field on a partial layer:
///
/// ```
/// use iroha_config_base::util::ExtendsPaths;
///
/// struct SomePartial {
///     extends: Option<ExtendsPaths>,
///     // ..other fields
/// }
/// ```
///
/// When this layer is constructed from a file, `ExtendsPaths` should be handled e.g.
/// with [`ExtendsPaths::iter`].
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(untagged)]
pub enum ExtendsPaths {
    /// A single path to extend from
    Single(PathBuf),
    /// A chain of paths to extend from
    Chain(Vec<PathBuf>),
}

/// Iterator over [`ExtendsPaths`] for convenience
pub enum ExtendsPathsIter<'a> {
    #[allow(missing_docs)]
    Single(Option<&'a PathBuf>),
    #[allow(missing_docs)]
    Chain(std::slice::Iter<'a, PathBuf>),
}

impl ExtendsPaths {
    /// Normalize into an iterator over a chain of paths to extend from
    #[allow(clippy::iter_without_into_iter)] // extra for this case
    pub fn iter(&self) -> ExtendsPathsIter<'_> {
        match &self {
            Self::Single(x) => ExtendsPathsIter::Single(Some(x)),
            Self::Chain(vec) => ExtendsPathsIter::Chain(vec.iter()),
        }
    }
}

impl<'a> Iterator for ExtendsPathsIter<'a> {
    type Item = &'a PathBuf;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Single(x) => x.take(),
            Self::Chain(iter) => iter.next(),
        }
    }
}

#[derive(Debug)]
pub struct Emitter<C> {
    report: Option<Report<C>>,
    bomb: DropBomb,
}

impl<C> Default for Emitter<C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C> Emitter<C> {
    pub fn new() -> Self {
        Self {
            report: None,
            bomb: DropBomb::new("haven't called `Emitter::into_result()`, have you?"),
        }
    }

    pub fn emit(&mut self, report: Report<C>) {
        match &mut self.report {
            Some(existing) => {
                existing.extend_one(report);
            }
            None => {
                self.report = Some(report);
            }
        }
    }

    pub fn into_result(mut self) -> error_stack::Result<(), C> {
        self.bomb.defuse();
        self.report.map_or_else(|| Ok(()), Err)
    }
}

pub trait EmitterResultExt<T, C> {
    fn ok_or_emit(self, emitter: &mut Emitter<C>) -> Option<T>;
}

impl<T, C> EmitterResultExt<T, C> for error_stack::Result<T, C> {
    fn ok_or_emit(self, emitter: &mut Emitter<C>) -> Option<T> {
        self.map_or_else(
            |report| {
                emitter.emit(report);
                None
            },
            Some,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct TestExtends {
        extends: Option<ExtendsPaths>,
    }

    #[test]
    fn parse_empty_extends() {
        let value: TestExtends = toml::from_str("").expect("should be fine with empty input");

        assert_eq!(value.extends, None);
    }

    #[test]
    fn parse_single_extends_path() {
        let value: TestExtends = toml::toml! {
            extends = "./path"
        }
        .try_into()
        .unwrap();

        assert_eq!(value.extends, Some(ExtendsPaths::Single("./path".into())));
    }

    #[test]
    fn parse_multiple_extends_paths() {
        let value: TestExtends = toml::toml! {
            extends = ["foo", "bar", "baz"]
        }
        .try_into()
        .unwrap();

        assert_eq!(
            value.extends,
            Some(ExtendsPaths::Chain(vec![
                "foo".into(),
                "bar".into(),
                "baz".into()
            ]))
        );
    }

    #[test]
    fn iterating_over_extends() {
        impl ExtendsPaths {
            fn as_str_vec(&self) -> Vec<&str> {
                self.iter().map(|p| p.to_str().unwrap()).collect()
            }
        }

        let single = ExtendsPaths::Single("single".into());
        assert_eq!(single.as_str_vec(), vec!["single"]);

        let multi = ExtendsPaths::Chain(vec!["foo".into(), "bar".into(), "baz".into()]);
        assert_eq!(multi.as_str_vec(), vec!["foo", "bar", "baz"]);
    }

    #[test]
    fn deserialize_human_duration() {
        #[derive(Deserialize)]
        struct Test {
            value: HumanDuration,
        }

        let Test { value } = toml::toml! {
            value = 10_500
        }
        .try_into()
        .expect("input is fine, should parse");

        assert_eq!(value.get(), Duration::from_millis(10_500));
    }
}
