//! Metadata: key-value pairs that can be attached to accounts,
//! transactions and assets.

#[cfg(not(feature = "std"))]
use alloc::{collections::btree_map, fmt, format, string::String, vec::Vec};
use core::borrow::Borrow;
#[cfg(feature = "std")]
use std::{collections::btree_map, fmt};

use derive_more::Display;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::{Name, Value};

/// Collection of parameters by their names.
pub type UnlimitedMetadata = btree_map::BTreeMap<Name, Value>;

/// Limits for [`Metadata`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, Deserialize, Serialize)]
pub struct Limits {
    /// Maximum number of entries
    pub max_len: u32,
    /// Maximum length of entry
    pub max_entry_byte_size: u32,
}

impl fmt::Display for Limits {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Metadata related errors.
#[derive(Debug, Clone, Display)]
pub enum Error {
    /// Metadata entry too big.
    #[display(fmt = "Metadata entry too big {} - {}", limits, actual)]
    EntrySize {
        /// The limits that were set for this entry
        limits: Limits,
        /// The actual *entry* size in bytes
        actual: usize,
    },
    /// Metadata exceeds overall length limit
    #[display(fmt = "Metadata exceeds overall length limit {} - {}", limits, actual)]
    OverallSize {
        /// The limits that were set for this entry
        limits: Limits,
        /// The actual *overall* size of metadata
        actual: usize,
    },
    /// Empty path
    #[display(fmt = "Path specification empty")]
    EmptyPath,
    /// Middle path segment is missing. I.e. nothing was found at that key
    #[display(fmt = "{}: path segment not found", _0)]
    MissingSegment(Name),
    /// Middle path segment is not nested metadata. I.e. something was found, but isn't an instance of [`Metadata`]
    #[display(fmt = "{}: path segment not an instance of metadata", _0)]
    InvalidSegment(Name),
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl Limits {
    /// Constructor.
    pub const fn new(max_len: u32, max_entry_byte_size: u32) -> Limits {
        Limits {
            max_len,
            max_entry_byte_size,
        }
    }
}

/// Collection of parameters by their names with checked insertion.
#[derive(
    Debug,
    Clone,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    Deserialize,
    Serialize,
    IntoSchema,
)]
#[serde(transparent)]
pub struct Metadata {
    map: UnlimitedMetadata,
}

/// A path slice, composed of [`Name`]s.
pub type Path = [Name];

impl Metadata {
    /// Constructor.
    #[inline]
    pub fn new() -> Self {
        Self {
            map: btree_map::BTreeMap::new(),
        }
    }

    /// Get the (expensive) cumulative length of all [`Value`]s housed
    /// in this map.
    pub fn nested_len(&self) -> usize {
        self.map.iter().map(|(_, v)| 1 + v.len()).sum()
    }

    /// Get metadata given path. If the path is malformed, or
    /// incorrect (if e.g. any of interior path segments are not
    /// [`Metadata`] instances return `None`. Else borrow the value
    /// corresponding to that path.
    pub fn nested_get(&self, path: &Path) -> Option<&Value> {
        let key = path.last()?;
        let mut map = &self.map;
        for k in path.iter().take(path.len() - 1) {
            map = match map.get(k)? {
                Value::LimitedMetadata(data) => &data.map,
                _ => return None,
            };
        }
        map.get(key)
    }

    /// Remove leaf node in metadata, given path. If the path is
    /// malformed, or incorrect (if e.g. any of interior path segments
    /// are not [`Metadata`] instances) return `None`. Else return the
    /// owned value corresponding to that path.
    pub fn nested_remove(&mut self, path: &Path) -> Option<Value> {
        let key = path.last()?;
        let mut map = &mut self.map;
        for k in path.iter().take(path.len() - 1) {
            map = match map.get_mut(k)? {
                Value::LimitedMetadata(data) => &mut data.map,
                _ => return None,
            };
        }
        map.remove(key)
    }

    /// Insert the given [`Value`] into the given path. If the path is
    /// complete, check the limits and only then insert. The creation
    /// of the path is the responsibility of the user.
    ///
    /// # Errors
    /// - If the path is empty.
    /// - If one of the intermediate keys is absent.
    /// - If some intermediate key is a leaf node.
    pub fn nested_insert_with_limits(
        &mut self,
        path: &Path,
        value: Value,
        limits: Limits,
    ) -> Result<Option<Value>, Error> {
        if self.map.len() >= limits.max_len as usize {
            return Err(Error::OverallSize {
                limits,
                actual: self.map.len(),
            });
        }
        let key = path.last().ok_or(Error::EmptyPath)?;
        let mut layer = self;
        for k in path.iter().take(path.len() - 1) {
            layer = match layer
                .map
                .get_mut(k)
                .ok_or_else(|| Error::MissingSegment(k.clone()))?
            {
                Value::LimitedMetadata(data) => data,
                _ => return Err(Error::InvalidSegment(k.clone())),
            };
        }
        check_size_limits(key, value.clone(), limits)?;
        layer.insert_with_limits(key.clone(), value, limits)
    }

    /// Insert [`Value`] under the given key.  Returns `Some(value)`
    /// if the value was already present, `None` otherwise.
    ///
    /// # Errors
    /// Fails if `max_entry_byte_size` or `max_len` from `limits` are exceeded.
    pub fn insert_with_limits(
        &mut self,
        key: Name,
        value: Value,
        limits: Limits,
    ) -> Result<Option<Value>, Error> {
        if self.map.len() >= limits.max_len as usize && !self.map.contains_key(&key) {
            return Err(Error::OverallSize {
                limits,
                actual: self.map.len(),
            });
        }
        check_size_limits(&key, value.clone(), limits)?;
        Ok(self.map.insert(key, value))
    }

    /// Returns a `Some(reference)` to the value corresponding to
    /// the key, and `None` if not found.
    #[inline]
    pub fn get<K: Ord + ?Sized>(&self, key: &K) -> Option<&Value>
    where
        Name: Borrow<K>,
    {
        self.map.get(key)
    }

    /// Removes a key from the map, returning the owned
    /// `Some(value)` at the key if the key was previously in the
    /// map, else `None`.
    #[inline]
    pub fn remove<K: Ord + ?Sized>(&mut self, key: &K) -> Option<Value>
    where
        Name: Borrow<K>,
    {
        self.map.remove(key)
    }
}

fn check_size_limits(key: &Name, value: Value, limits: Limits) -> Result<(), Error> {
    let entry_bytes: Vec<u8> = (key, value).encode();
    let byte_size = entry_bytes.len();
    if byte_size > limits.max_entry_byte_size as usize {
        return Err(Error::EntrySize {
            limits,
            actual: byte_size,
        });
    }
    Ok(())
}

pub mod prelude {
    //! Prelude: re-export most commonly used traits, structs and macros from this module.
    pub use super::{Limits as MetadataLimits, Metadata, UnlimitedMetadata};
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    #[cfg(not(feature = "std"))]
    use alloc::{borrow::ToOwned as _, vec};
    use core::str::FromStr as _;

    use iroha_macro::FromVariant;

    use super::*;
    use crate::ParseError;

    /// Error used in testing to make text more readable using the `?` operator.
    #[derive(Debug, Display, Clone, FromVariant)]
    pub enum TestError {
        Parse(ParseError),
        Metadata(Error),
    }

    #[test]
    fn nested_fns_ignore_empty_path() {
        let mut metadata = Metadata::new();
        let empty_path = vec![];
        assert!(metadata.nested_get(&empty_path).is_none());
        assert!(metadata
            .nested_insert_with_limits(&empty_path, "0".to_owned().into(), Limits::new(12, 12))
            .is_err());
        assert!(metadata.nested_remove(&empty_path).is_none());
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn nesting_inserts_removes() -> Result<(), TestError> {
        let mut metadata = Metadata::new();
        let limits = Limits::new(1024, 1024);
        // TODO: If we allow a `unsafe`, we could create the path.
        metadata
            .insert_with_limits(Name::from_str("0")?, Metadata::new().into(), limits)
            .unwrap();
        metadata
            .nested_insert_with_limits(
                &[Name::from_str("0")?, Name::from_str("1")?],
                Metadata::new().into(),
                limits,
            )
            .unwrap();
        let path = [
            Name::from_str("0")?,
            Name::from_str("1")?,
            Name::from_str("2")?,
        ];
        metadata
            .nested_insert_with_limits(&path, "Hello World".to_owned().into(), limits)
            .unwrap();
        assert_eq!(
            *metadata.nested_get(&path).unwrap(),
            Value::from("Hello World".to_owned())
        );
        assert_eq!(metadata.nested_len(), 6); // Three nested path segments.
        metadata.nested_remove(&path);
        assert!(metadata.nested_get(&path).is_none());
        Ok(())
    }

    #[test]
    fn non_existent_path_segment_fails() -> Result<(), TestError> {
        let mut metadata = Metadata::new();
        let limits = Limits::new(10, 15);
        metadata.insert_with_limits(Name::from_str("0")?, Metadata::new().into(), limits)?;
        metadata.nested_insert_with_limits(
            &[Name::from_str("0")?, Name::from_str("1")?],
            Metadata::new().into(),
            limits,
        )?;
        let path = vec![
            Name::from_str("0")?,
            Name::from_str("1")?,
            Name::from_str("2")?,
        ];
        metadata.nested_insert_with_limits(&path, "Hello World".to_owned().into(), limits)?;
        let bad_path = vec![
            Name::from_str("0")?,
            Name::from_str("3")?,
            Name::from_str("2")?,
        ];
        assert!(metadata
            .nested_insert_with_limits(&bad_path, "Hello World".to_owned().into(), limits)
            .is_err());
        assert!(metadata.nested_get(&bad_path).is_none());
        assert!(metadata.nested_remove(&bad_path).is_none());
        Ok(())
    }

    #[test]
    fn nesting_respects_limits() -> Result<(), TestError> {
        let mut metadata = Metadata::new();
        let limits = Limits::new(10, 14);
        // TODO: If we allow a `unsafe`, we could create the path.
        metadata.insert_with_limits(Name::from_str("0")?, Metadata::new().into(), limits)?;
        metadata
            .nested_insert_with_limits(
                &[Name::from_str("0")?, Name::from_str("1")?],
                Metadata::new().into(),
                limits,
            )
            .unwrap();
        let path = vec![
            Name::from_str("0")?,
            Name::from_str("1")?,
            Name::from_str("2")?,
        ];
        let failing_insert =
            metadata.nested_insert_with_limits(&path, "Hello World".to_owned().into(), limits);

        assert!(failing_insert.is_err());
        Ok(())
    }

    #[test]
    fn insert_exceeds_entry_size() -> Result<(), TestError> {
        let mut metadata = Metadata::new();
        let limits = Limits::new(10, 5);
        assert!(metadata
            .insert_with_limits(Name::from_str("1")?, "2".to_owned().into(), limits)
            .is_ok());
        assert!(metadata
            .insert_with_limits(Name::from_str("1")?, "23456".to_owned().into(), limits)
            .is_err());
        Ok(())
    }

    #[test]
    // This test is a good candidate for both property-based and parameterised testing
    fn insert_exceeds_len() -> Result<(), TestError> {
        let mut metadata = Metadata::new();
        let limits = Limits::new(2, 5);
        assert!(metadata
            .insert_with_limits(Name::from_str("1")?, "0".to_owned().into(), limits)
            .is_ok());
        assert!(metadata
            .insert_with_limits(Name::from_str("2")?, "0".to_owned().into(), limits)
            .is_ok());
        assert!(metadata
            .insert_with_limits(Name::from_str("2")?, "1".to_owned().into(), limits)
            .is_ok());
        assert!(metadata
            .insert_with_limits(Name::from_str("3")?, "0".to_owned().into(), limits)
            .is_err());
        Ok(())
    }
}
