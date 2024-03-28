//! Metadata: key-value pairs that can be attached to accounts, transactions and assets.

#[cfg(not(feature = "std"))]
use alloc::{
    collections::btree_map,
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::borrow::Borrow;
#[cfg(feature = "std")]
use std::collections::btree_map;

use derive_more::Display;
use iroha_data_model_derive::model;
use iroha_macro::FromVariant;
use iroha_primitives::numeric::Numeric;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

pub use self::model::*;
use crate::Name;

/// A path slice, composed of [`Name`]s.
pub type Path = [Name];

/// Collection of parameters by their names.
pub type UnlimitedMetadata = btree_map::BTreeMap<Name, MetadataValueBox>;

#[model]
mod model {
    use super::*;

    /// Collection of parameters by their names with checked insertion.
    #[derive(
        Debug,
        Display,
        Clone,
        Default,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Deserialize,
        Serialize,
        Decode,
        Encode,
        IntoSchema,
    )]
    #[ffi_type(opaque)]
    #[repr(transparent)]
    #[serde(transparent)]
    #[display(fmt = "Metadata")]
    #[allow(clippy::multiple_inherent_impl)]
    pub struct Metadata(pub(super) btree_map::BTreeMap<Name, MetadataValueBox>);

    /// Metadata value
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        FromVariant,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[ffi_type(opaque)]
    #[allow(missing_docs)]
    pub enum MetadataValueBox {
        Bool(bool),
        String(String),
        Name(Name),
        Bytes(Vec<u8>),
        Numeric(Numeric),
        LimitedMetadata(Metadata),

        Vec(
            #[skip_from]
            #[skip_try_from]
            Vec<MetadataValueBox>,
        ),
    }

    /// Limits for [`Metadata`].
    #[derive(
        Debug,
        Display,
        Clone,
        Copy,
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
    #[ffi_type]
    #[display(fmt = "{capacity},{max_entry_len}_ML")]
    pub struct Limits {
        /// Maximum number of entries
        pub capacity: u32,
        /// Maximum length of entry
        pub max_entry_len: u32,
    }

    /// Metadata related errors.
    #[derive(
        Debug,
        displaydoc::Display,
        Clone,
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
    #[ffi_type(local)]
    #[cfg_attr(feature = "std", derive(thiserror::Error))]
    pub enum MetadataError {
        /// Path specification empty
        EmptyPath,
        /// Metadata entry is too big
        EntryTooBig(#[cfg_attr(feature = "std", source)] SizeError),
        /// Metadata exceeds overall length limit
        MaxCapacity(#[cfg_attr(feature = "std", source)] SizeError),
        /// `{0}`: path segment not found, i.e. nothing was found at that key
        MissingSegment(Name),
        /// `{0}`: path segment not an instance of metadata
        InvalidSegment(Name),
    }

    /// Size limits exhaustion error
    #[derive(
        Debug,
        Display,
        Copy,
        Clone,
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
    #[ffi_type]
    #[cfg_attr(feature = "std", derive(thiserror::Error))]
    #[display(fmt = "Limits are {limits}, while the actual value is {actual}")]
    pub struct SizeError {
        /// The limits that were set for this entry
        pub limits: Limits,
        /// The actual *entry* size in bytes
        pub actual: u64,
    }
}

impl Limits {
    /// Constructor.
    pub const fn new(capacity: u32, max_entry_len: u32) -> Limits {
        Limits {
            capacity,
            max_entry_len,
        }
    }
}

impl From<u32> for MetadataValueBox {
    fn from(value: u32) -> Self {
        Self::Numeric(value.into())
    }
}

impl From<u64> for MetadataValueBox {
    fn from(value: u64) -> Self {
        Self::Numeric(value.into())
    }
}

impl TryFrom<MetadataValueBox> for u32 {
    type Error = iroha_macro::error::ErrorTryFromEnum<MetadataValueBox, Self>;

    fn try_from(value: MetadataValueBox) -> Result<Self, Self::Error> {
        use iroha_macro::error::ErrorTryFromEnum;

        let MetadataValueBox::Numeric(numeric) = value else {
            return Err(ErrorTryFromEnum::default());
        };

        numeric.try_into().map_err(|_| ErrorTryFromEnum::default())
    }
}

impl TryFrom<MetadataValueBox> for u64 {
    type Error = iroha_macro::error::ErrorTryFromEnum<MetadataValueBox, Self>;

    fn try_from(value: MetadataValueBox) -> Result<Self, Self::Error> {
        use iroha_macro::error::ErrorTryFromEnum;

        let MetadataValueBox::Numeric(numeric) = value else {
            return Err(ErrorTryFromEnum::default());
        };

        numeric.try_into().map_err(|_| ErrorTryFromEnum::default())
    }
}

impl<V: Into<MetadataValueBox>> From<Vec<V>> for MetadataValueBox {
    fn from(values: Vec<V>) -> MetadataValueBox {
        MetadataValueBox::Vec(values.into_iter().map(Into::into).collect())
    }
}

impl<V> TryFrom<MetadataValueBox> for Vec<V>
where
    MetadataValueBox: TryInto<V>,
{
    type Error = iroha_macro::error::ErrorTryFromEnum<MetadataValueBox, Self>;

    fn try_from(value: MetadataValueBox) -> Result<Self, Self::Error> {
        if let MetadataValueBox::Vec(vec) = value {
            return vec
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_e| Self::Error::default());
        }

        Err(Self::Error::default())
    }
}

impl core::fmt::Display for MetadataValueBox {
    // TODO: Maybe derive
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MetadataValueBox::Bool(v) => core::fmt::Display::fmt(&v, f),
            MetadataValueBox::String(v) => core::fmt::Display::fmt(&v, f),
            MetadataValueBox::Name(v) => core::fmt::Display::fmt(&v, f),
            MetadataValueBox::Numeric(v) => core::fmt::Display::fmt(&v, f),
            MetadataValueBox::Bytes(v) => write!(f, "{v:?}"),
            MetadataValueBox::Vec(v) => {
                // TODO: Remove so we can derive.
                let list_of_display: Vec<_> = v.iter().map(ToString::to_string).collect();
                // this prints with quotation marks, which is fine 90%
                // of the time, and helps delineate where a display of
                // one value stops and another one begins.
                write!(f, "{list_of_display:?}")
            }
            MetadataValueBox::LimitedMetadata(v) => core::fmt::Display::fmt(&v, f),
        }
    }
}

#[allow(clippy::len_without_is_empty)]
impl MetadataValueBox {
    /// Number of underneath expressions.
    fn len(&self) -> usize {
        use MetadataValueBox::*;

        match self {
            Bool(_) | String(_) | Name(_) | Bytes(_) | Numeric(_) => 1,
            Vec(v) => v.iter().map(Self::len).sum::<usize>() + 1,
            LimitedMetadata(data) => data.nested_len() + 1,
        }
    }
}

impl Metadata {
    /// Constructor.
    #[inline]
    pub fn new() -> Self {
        Self(UnlimitedMetadata::new())
    }

    /// Get the (expensive) cumulative length of all [`Value`]s housed
    /// in this map.
    pub fn nested_len(&self) -> usize {
        self.0.values().map(|v| 1 + v.len()).sum()
    }

    /// Get metadata given path. If the path is malformed, or
    /// incorrect (if e.g. any of interior path segments are not
    /// [`Metadata`] instances return `None`. Else borrow the value
    /// corresponding to that path.
    pub fn nested_get(&self, path: &Path) -> Option<&MetadataValueBox> {
        let key = path.last()?;
        let mut map = &self.0;
        for k in path.iter().take(path.len() - 1) {
            map = match map.get(k)? {
                MetadataValueBox::LimitedMetadata(data) => &data.0,
                _ => return None,
            };
        }
        map.get(key)
    }

    /// Check if the internal map contains the given key.
    pub fn contains(&self, key: &Name) -> bool {
        self.0.contains_key(key)
    }

    /// Iterate over key/value pairs stored in the internal map.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&Name, &MetadataValueBox)> {
        self.0.iter()
    }

    /// Get the `Some(&Value)` associated to `key`. Return `None` if not found.
    #[inline]
    pub fn get<K: Ord + ?Sized>(&self, key: &K) -> Option<&MetadataValueBox>
    where
        Name: Borrow<K>,
    {
        self.0.get(key)
    }

    fn len_u64(&self) -> u64 {
        self.0
            .len()
            .try_into()
            .expect("`usize` should always fit into `u64`")
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
        value: impl Into<MetadataValueBox>,
        limits: Limits,
    ) -> Result<Option<MetadataValueBox>, MetadataError> {
        if self.0.len() >= limits.capacity as usize {
            return Err(MetadataError::MaxCapacity(SizeError {
                limits,
                actual: self.len_u64(),
            }));
        }
        let key = path.last().ok_or(MetadataError::EmptyPath)?;
        let mut layer = self;
        for k in path.iter().take(path.len() - 1) {
            layer = match layer
                .0
                .get_mut(k)
                .ok_or_else(|| MetadataError::MissingSegment(k.clone()))?
            {
                MetadataValueBox::LimitedMetadata(data) => data,
                _ => return Err(MetadataError::InvalidSegment(k.clone())),
            };
        }
        layer.insert_with_limits(key.clone(), value, limits)
    }

    /// Insert [`Value`] under the given key.  Returns `Some(value)`
    /// if the value was already present, `None` otherwise.
    ///
    /// # Errors
    /// Fails if `max_entry_len` or `capacity` from `limits` are exceeded.
    pub fn insert_with_limits(
        &mut self,
        key: Name,
        value: impl Into<MetadataValueBox>,
        limits: Limits,
    ) -> Result<Option<MetadataValueBox>, MetadataError> {
        let value = value.into();

        if self.0.len() >= limits.capacity as usize && !self.0.contains_key(&key) {
            return Err(MetadataError::MaxCapacity(SizeError {
                limits,
                actual: self.len_u64(),
            }));
        }
        check_size_limits(&key, value.clone(), limits)?;
        Ok(self.0.insert(key, value))
    }
}

#[cfg(feature = "transparent_api")]
impl Metadata {
    /// Removes a key from the map, returning the owned
    /// `Some(value)` at the key if the key was previously in the
    /// map, else `None`.
    #[inline]
    pub fn remove<K: Ord + ?Sized>(&mut self, key: &K) -> Option<MetadataValueBox>
    where
        Name: Borrow<K>,
    {
        self.0.remove(key)
    }

    /// Remove leaf node in metadata, given path. If the path is
    /// malformed, or incorrect (if e.g. any of interior path segments
    /// are not [`Metadata`] instances) return `None`. Else return the
    /// owned value corresponding to that path.
    pub fn nested_remove(&mut self, path: &Path) -> Option<MetadataValueBox> {
        let key = path.last()?;
        let mut map = &mut self.0;
        for k in path.iter().take(path.len() - 1) {
            map = match map.get_mut(k)? {
                MetadataValueBox::LimitedMetadata(data) => &mut data.0,
                _ => return None,
            };
        }
        map.remove(key)
    }
}

fn check_size_limits(
    key: &Name,
    value: MetadataValueBox,
    limits: Limits,
) -> Result<(), MetadataError> {
    let entry_bytes: Vec<u8> = (key, value).encode();
    let byte_size = entry_bytes.len();
    if byte_size > limits.max_entry_len as usize {
        return Err(MetadataError::EntryTooBig(SizeError {
            limits,
            actual: byte_size
                .try_into()
                .expect("`usize` should always fit into `u64`"),
        }));
    }
    Ok(())
}

pub mod prelude {
    //! Prelude: re-export most commonly used traits, structs and macros from this module.
    pub use super::{Limits as MetadataLimits, Metadata, UnlimitedMetadata};
}

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "std"))]
    use alloc::{borrow::ToOwned as _, vec};
    use core::str::FromStr as _;

    use super::*;
    use crate::ParseError;

    /// Error used in testing to make text more readable using the `?` operator.
    #[derive(Debug, Display, Clone, FromVariant)]
    pub enum TestError {
        Parse(ParseError),
        Metadata(MetadataError),
    }

    #[test]
    fn nested_fns_ignore_empty_path() {
        let mut metadata = Metadata::new();
        let empty_path = vec![];
        assert!(metadata.nested_get(&empty_path).is_none());
        assert!(metadata
            .nested_insert_with_limits(&empty_path, "0".to_owned(), Limits::new(12, 12))
            .is_err());
        #[cfg(feature = "transparent_api")]
        assert!(metadata.nested_remove(&empty_path).is_none());
    }

    #[test]
    #[cfg(feature = "transparent_api")]
    fn nesting_inserts_removes() -> Result<(), TestError> {
        let mut metadata = Metadata::new();
        let limits = Limits::new(1024, 1024);
        // TODO: If we allow a `unsafe`, we could create the path.
        metadata
            .insert_with_limits(Name::from_str("0")?, Metadata::new(), limits)
            .expect("Valid");
        metadata
            .nested_insert_with_limits(
                &[Name::from_str("0")?, Name::from_str("1")?],
                Metadata::new(),
                limits,
            )
            .expect("Valid");
        let path = [
            Name::from_str("0")?,
            Name::from_str("1")?,
            Name::from_str("2")?,
        ];
        metadata
            .nested_insert_with_limits(&path, "Hello World".to_owned(), limits)
            .expect("Valid");
        assert_eq!(
            *metadata.nested_get(&path).expect("Valid"),
            MetadataValueBox::from("Hello World".to_owned())
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
        metadata.insert_with_limits(Name::from_str("0")?, Metadata::new(), limits)?;
        metadata.nested_insert_with_limits(
            &[Name::from_str("0")?, Name::from_str("1")?],
            Metadata::new(),
            limits,
        )?;
        let path = vec![
            Name::from_str("0")?,
            Name::from_str("1")?,
            Name::from_str("2")?,
        ];
        metadata.nested_insert_with_limits(&path, "Hello World".to_owned(), limits)?;
        let bad_path = vec![
            Name::from_str("0")?,
            Name::from_str("3")?,
            Name::from_str("2")?,
        ];
        assert!(metadata
            .nested_insert_with_limits(&bad_path, "Hello World".to_owned(), limits)
            .is_err());
        assert!(metadata.nested_get(&bad_path).is_none());
        #[cfg(feature = "transparent_api")]
        assert!(metadata.nested_remove(&bad_path).is_none());
        Ok(())
    }

    #[test]
    fn nesting_respects_limits() -> Result<(), TestError> {
        let mut metadata = Metadata::new();
        let limits = Limits::new(10, 14);
        // TODO: If we allow a `unsafe`, we could create the path.
        metadata.insert_with_limits(Name::from_str("0")?, Metadata::new(), limits)?;
        metadata
            .nested_insert_with_limits(
                &[Name::from_str("0")?, Name::from_str("1")?],
                Metadata::new(),
                limits,
            )
            .expect("Valid");
        let path = vec![
            Name::from_str("0")?,
            Name::from_str("1")?,
            Name::from_str("2")?,
        ];
        let failing_insert =
            metadata.nested_insert_with_limits(&path, "Hello World".to_owned(), limits);

        assert!(failing_insert.is_err());
        Ok(())
    }

    #[test]
    fn insert_exceeds_entry_size() -> Result<(), TestError> {
        let mut metadata = Metadata::new();
        let limits = Limits::new(10, 5);
        assert!(metadata
            .insert_with_limits(Name::from_str("1")?, "2".to_owned(), limits)
            .is_ok());
        assert!(metadata
            .insert_with_limits(Name::from_str("1")?, "23456".to_owned(), limits)
            .is_err());
        Ok(())
    }

    #[test]
    // This test is a good candidate for both property-based and parameterised testing
    fn insert_exceeds_len() -> Result<(), TestError> {
        let mut metadata = Metadata::new();
        let limits = Limits::new(2, 5);
        assert!(metadata
            .insert_with_limits(Name::from_str("1")?, "0".to_owned(), limits)
            .is_ok());
        assert!(metadata
            .insert_with_limits(Name::from_str("2")?, "0".to_owned(), limits)
            .is_ok());
        assert!(metadata
            .insert_with_limits(Name::from_str("2")?, "1".to_owned(), limits)
            .is_ok());
        assert!(metadata
            .insert_with_limits(Name::from_str("3")?, "0".to_owned(), limits)
            .is_err());
        Ok(())
    }
}
