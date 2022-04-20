//! Module for schematizing rust types in other languages for translation.

#![no_std]

extern crate alloc;

use alloc::{
    boxed::Box,
    collections::{btree_map::BTreeMap, btree_set::BTreeSet},
    format,
    string::String,
    vec,
    vec::Vec,
};

/// Derive schema. It will make your structure schemaable
pub use iroha_schema_derive::IntoSchema;
use serde::Serialize;

/// Metadata map
pub type MetaMap = BTreeMap<String, Metadata>;

/// `IntoSchema` trait
pub trait IntoSchema {
    /// Returns unique type name.
    // TODO: Should return &str if possible or be immutable string
    fn type_name() -> String;

    /// Returns info about current type. Will return map from type names to its metadata
    fn get_schema() -> MetaMap {
        let mut map = MetaMap::new();
        Self::schema(&mut map);
        map
    }

    /// `IntoSchema` function. Give it empty map and it will return description of types
    /// related to this type
    fn schema(metamap: &mut MetaMap);
}

/// Applicable for types that represents decimal place of fixed point
pub trait DecimalPlacesAware {
    /// decimal places of fixed point
    fn decimal_places() -> u32;
}

/// Metadata
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
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
    Option(String),
    /// Result
    Result(ResultMeta),
}

/// Array metadata
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct ArrayMeta {
    /// Type
    pub ty: String,
    /// Length
    pub len: u64,
    /// Order elements
    pub sorted: bool,
}

/// Array metadata
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct VecMeta {
    /// Type
    pub ty: String,
    /// Order elements
    pub sorted: bool,
}

/// Named fields
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct NamedFieldsMeta {
    /// Fields
    pub declarations: Vec<Declaration>,
}

/// Field
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Declaration {
    /// Field name
    pub name: String,
    /// Type
    pub ty: String,
}

/// Unnamed fields
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct UnnamedFieldsMeta {
    /// Field types
    pub types: Vec<String>,
}

/// Enum metadata
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct EnumMeta {
    /// Enum variants
    pub variants: Vec<EnumVariant>,
}

/// Enum variant
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct EnumVariant {
    /// Enum variant name
    pub name: String,
    /// Its discriminant (or identifier)
    pub discriminant: u8,
    /// Its type
    pub ty: Option<String>,
}

/// Result variant
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct ResultMeta {
    /// Ok type
    pub ok: String,
    /// Err type
    pub err: String,
}
/// Map variant
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct MapMeta {
    /// Key type
    pub key: String,
    /// Value type
    pub value: String,
    /// Order key-value pairs by key
    pub sorted_by_key: bool,
}

/// Integer mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum IntMode {
    /// Fixed width
    FixedWidth,
    /// Scale compact
    Compact,
}

/// Compact predicate. Just for documentation purposes
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Compact<T>(T);

/// Fixed metadata
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct FixedMeta {
    base: String,
    decimal_places: u32,
}

macro_rules! impl_schema_int {
    ($($t:ty),*) => {$(
        impl IntoSchema for $t {
            fn type_name() -> String {
                String::from(stringify!($t))
            }
            fn schema(map: &mut MetaMap) {
                let _ = map.entry(Self::type_name()).or_insert(
                    Metadata::Int(IntMode::FixedWidth),
                );
            }
        }

        impl IntoSchema for Compact<$t> {
            fn type_name() -> String {
                format!("Compact<{}>", <$t as IntoSchema>::type_name())
            }
            fn schema(map: &mut MetaMap) {
                let _ = map.entry(Self::type_name()).or_insert(Metadata::Int(IntMode::Compact));
            }
        }
    )*};
}

impl_schema_int!(u128, u64, u32, u16, u8, i128, i64, i32, i16, i8);

impl<I: IntoSchema, P: DecimalPlacesAware> IntoSchema for fixnum::FixedPoint<I, P> {
    fn type_name() -> String {
        format!("FixedPoint<{}>", I::type_name())
    }

    fn schema(metamap: &mut MetaMap) {
        let _ = metamap.entry(Self::type_name()).or_insert_with(|| {
            Metadata::FixedPoint(FixedMeta {
                base: I::type_name(),
                decimal_places: P::decimal_places(),
            })
        });
        if !metamap.contains_key(&I::type_name()) {
            I::schema(metamap);
        }
    }
}

impl DecimalPlacesAware for fixnum::typenum::U9 {
    fn decimal_places() -> u32 {
        9
    }
}

impl IntoSchema for String {
    fn type_name() -> String {
        String::from("String")
    }
    fn schema(map: &mut MetaMap) {
        let _ = map.entry(Self::type_name()).or_insert(Metadata::String);
    }
}

impl IntoSchema for bool {
    fn type_name() -> String {
        String::from("bool")
    }
    fn schema(map: &mut MetaMap) {
        let _ = map.entry(Self::type_name()).or_insert(Metadata::Bool);
    }
}

impl<T: IntoSchema> IntoSchema for Vec<T> {
    fn type_name() -> String {
        format!("Vec<{}>", T::type_name())
    }
    fn schema(map: &mut MetaMap) {
        let _ = map.entry(Self::type_name()).or_insert_with(|| {
            Metadata::Vec(VecMeta {
                ty: T::type_name(),
                sorted: false,
            })
        });
        if !map.contains_key(&T::type_name()) {
            T::schema(map);
        }
    }
}

impl<T: IntoSchema> IntoSchema for Option<T> {
    fn type_name() -> String {
        format!("Option<{}>", T::type_name())
    }
    fn schema(map: &mut MetaMap) {
        let _ = map
            .entry(Self::type_name())
            .or_insert_with(|| Metadata::Option(T::type_name()));
        if !map.contains_key(&T::type_name()) {
            T::schema(map);
        }
    }
}

impl<T: IntoSchema> IntoSchema for Box<T> {
    fn type_name() -> String {
        T::type_name()
    }

    fn schema(map: &mut MetaMap) {
        T::schema(map)
    }
}

impl<T: IntoSchema, E: IntoSchema> IntoSchema for Result<T, E> {
    fn type_name() -> String {
        format!("Result<{}, {}>", T::type_name(), E::type_name())
    }
    fn schema(map: &mut MetaMap) {
        let _ = map.entry(Self::type_name()).or_insert_with(|| {
            Metadata::Result(ResultMeta {
                ok: T::type_name(),
                err: E::type_name(),
            })
        });
        if !map.contains_key(&T::type_name()) {
            T::schema(map);
        }
        if !map.contains_key(&E::type_name()) {
            E::schema(map);
        }
    }
}

impl<K: IntoSchema, V: IntoSchema> IntoSchema for BTreeMap<K, V> {
    fn type_name() -> String {
        format!("Map<{}, {}>", K::type_name(), V::type_name(),)
    }
    fn schema(map: &mut MetaMap) {
        map.entry(Self::type_name()).or_insert_with(|| {
            Metadata::Map(MapMeta {
                key: K::type_name(),
                value: V::type_name(),
                sorted_by_key: true,
            })
        });

        if !map.contains_key(&K::type_name()) {
            K::schema(map);
        }
        if !map.contains_key(&V::type_name()) {
            V::schema(map);
        }
    }
}

impl<K: IntoSchema> IntoSchema for BTreeSet<K> {
    fn type_name() -> String {
        format!("Vec<{}>", K::type_name())
    }
    fn schema(map: &mut MetaMap) {
        map.entry(Self::type_name()).or_insert_with(|| {
            Metadata::Vec(VecMeta {
                ty: K::type_name(),
                sorted: true,
            })
        });
        if !map.contains_key(&K::type_name()) {
            K::schema(map)
        }
    }
}

impl IntoSchema for core::time::Duration {
    fn type_name() -> String {
        String::from("Duration")
    }
    // Look at:
    //   https://docs.rs/parity-scale-codec/2.1.1/src/parity_scale_codec/codec.rs.html#1182-1192
    fn schema(map: &mut MetaMap) {
        let _ = map.entry(Self::type_name()).or_insert_with(|| {
            Metadata::Tuple(UnnamedFieldsMeta {
                types: vec![u64::type_name(), u32::type_name()],
            })
        });
        if !map.contains_key("u64") {
            u64::schema(map);
        }
        if !map.contains_key("u32") {
            u32::schema(map);
        }
    }
}

impl<T: IntoSchema, const L: usize> IntoSchema for [T; L] {
    fn type_name() -> String {
        format!("[{}; {}]", T::type_name(), L)
    }

    fn schema(map: &mut MetaMap) {
        let _ = map.entry(Self::type_name()).or_insert_with(|| {
            #[allow(clippy::expect_used)]
            Metadata::Array(ArrayMeta {
                ty: T::type_name(),
                len: L.try_into().expect("usize should always fit in u64"),
                sorted: false,
            })
        });
        if !map.contains_key(&T::type_name()) {
            T::schema(map);
        }
    }
}

pub mod prelude {
    //! Exports common types.

    pub use super::*;
}
