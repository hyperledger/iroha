//! Module for schematizing rust types in other languages for translation.

#![no_std]

extern crate alloc;

mod serialize;

use alloc::{
    borrow::ToOwned as _,
    boxed::Box,
    collections::{btree_map, btree_set},
    format,
    string::String,
    vec,
    vec::Vec,
};
use core::{
    num::{NonZeroU16, NonZeroU32, NonZeroU64},
    ops::RangeInclusive,
};

/// Derive schema. It will make your structure schemaable
pub use iroha_schema_derive::*;
use serde::Serialize;

/// An entry in the schema map
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MetaMapEntry {
    /// A unique identifier of the type
    pub type_id: String,
    /// The name under which the type is exposed in the schema
    pub type_name: String,
    /// Details about the type representation
    pub metadata: Metadata,
}

/// Helper struct for building a full schema
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MetaMap(pub(crate) btree_map::BTreeMap<core::any::TypeId, MetaMapEntry>);

impl PartialEq<btree_map::BTreeMap<core::any::TypeId, MetaMapEntry>> for MetaMap {
    fn eq(&self, other: &btree_map::BTreeMap<core::any::TypeId, MetaMapEntry>) -> bool {
        self.0.eq(other)
    }
}

impl MetaMap {
    fn key<K: 'static>() -> core::any::TypeId {
        core::any::TypeId::of::<K>()
    }

    /// Create new [`Self`]
    #[must_use]
    pub const fn new() -> MetaMap {
        Self(btree_map::BTreeMap::new())
    }
    /// Return `true` if the map contains a metadata for the specified [`core::any::TypeId`]
    pub fn contains_key<K: 'static>(&self) -> bool {
        self.0.contains_key(&Self::key::<K>())
    }
    /// Remove a key-value pair from the map.
    pub fn remove<K: IntoSchema>(&mut self) -> bool {
        self.0.remove(&Self::key::<K>()).is_some()
    }
    /// Insert a key-value pair into the map.
    pub fn insert<K: IntoSchema>(&mut self, metadata: Metadata) -> bool {
        self.0
            .insert(Self::key::<K>(), {
                MetaMapEntry {
                    type_id: K::id(),
                    type_name: K::type_name(),
                    metadata,
                }
            })
            .is_none()
    }
    /// Return a reference to the value corresponding to the [`core::any::TypeId`] of the schema type
    pub fn get<K: 'static>(&self) -> Option<&Metadata> {
        self.0.get(&Self::key::<K>()).map(|value| &value.metadata)
    }
}

impl IntoIterator for MetaMap {
    type Item = (core::any::TypeId, MetaMapEntry);
    type IntoIter = btree_map::IntoIter<core::any::TypeId, MetaMapEntry>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

// TODO: Should be &str or ConstString.
/// Identifier of the type
pub type Ident = String;

/// Globally unique type identifier
///
/// No critical code should rely on this trait unless a test
/// is devised that can prove that all impls are unique
pub trait TypeId: 'static {
    /// Return unique type id
    fn id() -> Ident;
}

/// `IntoSchema` trait
pub trait IntoSchema: TypeId {
    /// Name under which a type is represented in the schema
    fn type_name() -> Ident;

    /// Insert descriptions of types referenced by [`Self`]
    fn update_schema_map(metamap: &mut MetaMap);

    /// Remove description of types referenced by [`Self`]
    fn remove_from_schema(metamap: &mut MetaMap) -> bool
    where
        Self: Sized,
    {
        metamap.remove::<Self>()
    }

    /// Return schema map of types referenced by [`Self`]
    #[must_use]
    fn schema() -> MetaMap {
        let mut map = MetaMap::new();
        Self::update_schema_map(&mut map);
        map
    }
}

/// Applicable for types that represents decimal place of fixed point
pub trait DecimalPlacesAware: 'static {
    /// decimal places of fixed point
    fn decimal_places() -> u32;
}

/// Metadata
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Metadata {
    /// Structure with named fields
    Struct(NamedFieldsMeta),
    /// Unnamed structure
    Tuple(UnnamedFieldsMeta),
    /// Enum
    Enum(EnumMeta),
    /// Integer
    Int(IntMode),
    /// String
    String,
    /// Bool
    Bool,
    /// Number with fixed decimal precision
    FixedPoint(FixedMeta),
    /// Array
    Array(ArrayMeta),
    /// Vector with type
    Vec(VecMeta),
    /// Associative array
    Map(MapMeta),
    /// Option with type
    Option(core::any::TypeId),
    /// Result
    Result(ResultMeta),
    /// A bitmap: integer where bits have a specific meaning
    Bitmap(BitmapMeta),
}

/// Array metadata
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ArrayMeta {
    /// Type
    pub ty: core::any::TypeId,
    /// Length
    pub len: u64,
}

/// Vector metadata
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VecMeta {
    /// Type
    pub ty: core::any::TypeId,
}

/// Named fields
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NamedFieldsMeta {
    /// Fields
    pub declarations: Vec<Declaration>,
}

/// Field
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Declaration {
    /// Field name
    pub name: String,
    /// Type
    pub ty: core::any::TypeId,
}

/// Unnamed fields
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UnnamedFieldsMeta {
    /// Field types
    pub types: Vec<core::any::TypeId>,
}

/// Enum metadata
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EnumMeta {
    /// Enum variants
    pub variants: Vec<EnumVariant>,
}

/// Enum variant
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EnumVariant {
    /// Enum variant name
    pub tag: String,
    /// Its discriminant (or identifier)
    pub discriminant: u8,
    /// Its type
    pub ty: Option<core::any::TypeId>,
}

/// Result variant
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResultMeta {
    /// Ok type
    pub ok: core::any::TypeId,
    /// Err type
    pub err: core::any::TypeId,
}
/// Map variant
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MapMeta {
    /// Key type
    pub key: core::any::TypeId,
    /// Value type
    pub value: core::any::TypeId,
}

/// Fixed metadata
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FixedMeta {
    /// Base type
    pub base: core::any::TypeId,
    /// Decimal places
    pub decimal_places: u32,
}

/// Integer mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum IntMode {
    /// Fixed width
    FixedWidth,
    /// Scale compact
    Compact,
}

/// Bitmap metadata
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BitmapMeta {
    /// Underlying integer type
    pub repr: core::any::TypeId,
    /// Masks, specifying the meaning of the bits
    pub masks: Vec<BitmapMask>,
}

/// Bitmap mask
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct BitmapMask {
    /// Symbolic name of the mask
    pub name: String,
    /// Mask value
    // while we can technically have masks with multiple bits set or intersecting masks, we currently only emit single-bit disjoint masks
    pub mask: u64,
}

/// Compact predicate. Just for documentation purposes
#[derive(Debug, Clone, Serialize)]
pub struct Compact<T>(T);

impl TypeId for () {
    fn id() -> String {
        "()".to_owned()
    }
}
impl IntoSchema for () {
    fn type_name() -> String {
        "()".to_owned()
    }
    fn update_schema_map(map: &mut MetaMap) {
        if !map.contains_key::<Self>() {
            map.insert::<Self>(Metadata::Tuple(UnnamedFieldsMeta { types: vec![] }));
        }
    }
}

macro_rules! impl_schema_int {
    ($($t:ty),*) => {$(
        impl TypeId for $t {
            fn id() -> String {
                stringify!($t).to_owned()
            }
        }
        impl IntoSchema for $t {
            fn type_name() -> String {
                stringify!($t).to_owned()
            }
            fn update_schema_map(map: &mut MetaMap) {
                if !map.contains_key::<Self>() {
                    map.insert::<Self>(Metadata::Int(IntMode::FixedWidth));
                }
            }
        }

        impl TypeId for Compact<$t> {
            fn id() -> String {
                format!("Compact<{}>", <$t as TypeId>::id())
            }
        }
        impl IntoSchema for Compact<$t> {
            fn type_name() -> String {
                format!("Compact<{}>", <$t as IntoSchema>::type_name())
            }

            fn update_schema_map(map: &mut MetaMap) {
                if !map.contains_key::<Self>() {
                    map.insert::<Self>(Metadata::Int(IntMode::Compact));
                }
            }
        }
    )*};
}
impl_schema_int!(u128, u64, u32, u16, u8, i128, i64, i32, i16, i8);

macro_rules! impl_schema_non_zero_int {
    ($($src:ty => $dst:ty),*) => {$(
        impl TypeId for $src {
            fn id() -> String {
                format!("NonZero<{}>", <$dst as TypeId>::id())
            }
        }
        impl IntoSchema for $src {
            fn type_name() -> String {
                format!("NonZero<{}>", <$dst as IntoSchema>::type_name())
            }
            fn update_schema_map(map: &mut MetaMap) {
                if !map.contains_key::<Self>() {
                    map.insert::<Self>(Metadata::Tuple(UnnamedFieldsMeta {
                        types: vec![core::any::TypeId::of::<$dst>()],
                    }));

                    <$dst as IntoSchema>::update_schema_map(map);
                }
            }
        }
    )*};
}

impl_schema_non_zero_int!(NonZeroU64 => u64, NonZeroU32 => u32, NonZeroU16 => u16);

impl TypeId for String {
    fn id() -> String {
        "String".to_owned()
    }
}
impl IntoSchema for String {
    fn type_name() -> String {
        "String".to_owned()
    }
    fn update_schema_map(map: &mut MetaMap) {
        if !map.contains_key::<Self>() {
            map.insert::<Self>(Metadata::String);
        }
    }
}

impl TypeId for bool {
    fn id() -> String {
        "bool".to_owned()
    }
}
impl IntoSchema for bool {
    fn type_name() -> String {
        "bool".to_owned()
    }
    fn update_schema_map(map: &mut MetaMap) {
        if !map.contains_key::<Self>() {
            map.insert::<Self>(Metadata::Bool);
        }
    }
}

impl<T: TypeId> TypeId for Vec<T> {
    fn id() -> String {
        format!("Vec<{}>", T::id())
    }
}
impl<T: IntoSchema> IntoSchema for Vec<T> {
    fn type_name() -> String {
        format!("Vec<{}>", T::type_name())
    }
    fn update_schema_map(map: &mut MetaMap) {
        if !map.contains_key::<Self>() {
            map.insert::<Self>(Metadata::Vec(VecMeta {
                ty: core::any::TypeId::of::<T>(),
            }));

            T::update_schema_map(map);
        }
    }
}

impl<T: TypeId> TypeId for Option<T> {
    fn id() -> String {
        format!("Option<{}>", T::id())
    }
}
impl<T: IntoSchema> IntoSchema for Option<T> {
    fn type_name() -> String {
        format!("Option<{}>", T::type_name())
    }
    fn update_schema_map(map: &mut MetaMap) {
        if !map.contains_key::<Self>() {
            let t_type_id = core::any::TypeId::of::<T>();
            map.insert::<Self>(Metadata::Option(t_type_id));

            T::update_schema_map(map);
        }
    }
}

impl<T: TypeId> TypeId for Box<T> {
    fn id() -> String {
        format!("Box<{}>", T::id())
    }
}
impl<T: IntoSchema> IntoSchema for Box<T> {
    fn type_name() -> String {
        T::type_name()
    }
    fn update_schema_map(map: &mut MetaMap) {
        if !map.contains_key::<Self>() {
            if !map.contains_key::<T>() {
                T::update_schema_map(map);
            }

            if let Some(schema) = map.get::<T>() {
                map.insert::<Self>(schema.clone());
            }
        }
    }
}

impl TypeId for Box<str> {
    fn id() -> String {
        "String".to_owned()
    }
}
impl IntoSchema for Box<str> {
    fn type_name() -> String {
        "String".to_owned()
    }
    fn update_schema_map(map: &mut MetaMap) {
        if !map.contains_key::<Self>() {
            if !map.contains_key::<String>() {
                String::update_schema_map(map);
            }

            if let Some(schema) = map.get::<String>() {
                map.insert::<Self>(schema.clone());
            }
        }
    }
}

impl<T: TypeId, E: TypeId> TypeId for Result<T, E> {
    fn id() -> String {
        format!("Result<{}, {}>", T::id(), E::id())
    }
}
impl<T: IntoSchema, E: IntoSchema> IntoSchema for Result<T, E> {
    fn type_name() -> String {
        format!("Result<{}, {}>", T::type_name(), E::type_name())
    }
    fn update_schema_map(map: &mut MetaMap) {
        if !map.contains_key::<Self>() {
            map.insert::<Self>(Metadata::Result(ResultMeta {
                ok: core::any::TypeId::of::<T>(),
                err: core::any::TypeId::of::<E>(),
            }));

            T::update_schema_map(map);
            E::update_schema_map(map);
        }
    }
}

impl<K: TypeId, V: TypeId> TypeId for btree_map::BTreeMap<K, V> {
    fn id() -> String {
        format!("SortedMap<{}, {}>", K::id(), V::id(),)
    }
}
impl<K: IntoSchema, V: IntoSchema> IntoSchema for btree_map::BTreeMap<K, V> {
    fn type_name() -> String {
        format!("SortedMap<{}, {}>", K::type_name(), V::type_name(),)
    }
    fn update_schema_map(map: &mut MetaMap) {
        if !map.contains_key::<Self>() {
            map.insert::<Self>(Metadata::Map(MapMeta {
                key: core::any::TypeId::of::<K>(),
                value: core::any::TypeId::of::<V>(),
            }));

            K::update_schema_map(map);
            V::update_schema_map(map);
        }
    }
}

impl<K: TypeId> TypeId for btree_set::BTreeSet<K> {
    fn id() -> String {
        format!("SortedVec<{}>", K::id())
    }
}
impl<K: IntoSchema> IntoSchema for btree_set::BTreeSet<K> {
    fn type_name() -> String {
        format!("SortedVec<{}>", K::type_name())
    }
    fn update_schema_map(map: &mut MetaMap) {
        if !map.contains_key::<Self>() {
            map.insert::<Self>(Metadata::Vec(VecMeta {
                ty: core::any::TypeId::of::<K>(),
            }));

            K::update_schema_map(map);
        }
    }
}

impl<T: TypeId, const L: usize> TypeId for [T; L] {
    fn id() -> String {
        format!("Array<{}, {}>", T::id(), L)
    }
}
impl<T: IntoSchema, const L: usize> IntoSchema for [T; L] {
    fn type_name() -> String {
        format!("Array<{}, {}>", T::type_name(), L)
    }
    fn update_schema_map(map: &mut MetaMap) {
        if !map.contains_key::<Self>() {
            map.insert::<Self>(Metadata::Array(ArrayMeta {
                ty: core::any::TypeId::of::<T>(),
                len: L.try_into().expect("usize should always fit in u64"),
            }));

            T::update_schema_map(map);
        }
    }
}

impl<T: TypeId> TypeId for RangeInclusive<T> {
    fn id() -> String {
        format!("RangeInclusive<{}>", T::id())
    }
}

impl<T: IntoSchema> IntoSchema for RangeInclusive<T> {
    fn type_name() -> String {
        format!("RangeInclusive<{}>", T::type_name())
    }

    fn update_schema_map(metamap: &mut MetaMap) {
        if !metamap.contains_key::<Self>() {
            metamap.insert::<Self>(Metadata::Tuple(UnnamedFieldsMeta {
                types: vec![core::any::TypeId::of::<T>(), core::any::TypeId::of::<T>()],
            }));

            T::update_schema_map(metamap);
        }
    }
}

pub mod prelude {
    //! Exports common types.

    pub use super::*;
}
