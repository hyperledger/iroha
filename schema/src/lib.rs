//! Module for schematizing rust types in other languages for translation.

#![allow(clippy::expect_used)]
#![no_std]

extern crate alloc;

use alloc::{
    borrow::ToOwned as _,
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
    /// WARN: `core::any::type_name` is compiler related, so is not unique.
    /// I guess we should change it somehow later
    // TODO: Should return &str if possible
    fn type_name() -> String {
        core::any::type_name::<Self>()
            .replace("alloc::string::String", "String")
            .replace("alloc::vec::Vec", "Vec")
    }

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
    /// Structure with unnamed fields
    TupleStruct(UnnamedFieldsMeta),
    /// Enumeration
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
    Vec(String),
    /// Map
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
}

/// Named fields
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct NamedFieldsMeta {
    /// Fields
    pub declarations: Vec<Declaration>,
    //todo add collection of properties meta defined in struct
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
    // TODO: add collection of properties meta defined in struct
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
    //todo add collection of properties meta defined in enum variant
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
    ($($t:ty,)*) => {$(
        impl IntoSchema for $t {
            fn type_name() -> String {
                core::any::type_name::<Self>().to_owned()
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

impl_schema_int!(u128, u64, u32, u16, u8, i128, i64, i32, i16, i8,);

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
        "String".to_owned()
    }
    fn schema(map: &mut MetaMap) {
        let _ = map.entry(Self::type_name()).or_insert(Metadata::String);
    }
}

impl IntoSchema for bool {
    fn type_name() -> String {
        core::any::type_name::<Self>().to_owned()
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
        let _ = map
            .entry(Self::type_name())
            .or_insert_with(|| Metadata::Vec(T::type_name()));
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

impl<T: IntoSchema> IntoSchema for alloc::boxed::Box<T> {
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
        format!("BTreeMap<{}, {}>", K::type_name(), V::type_name())
    }
    fn schema(map: &mut MetaMap) {
        let _ = map.entry(Self::type_name()).or_insert_with(|| {
            Metadata::Map(MapMeta {
                key: K::type_name(),
                value: V::type_name(),
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

impl<V: IntoSchema> IntoSchema for BTreeSet<V> {
    fn type_name() -> String {
        format!("BTreeSet<{}>", V::type_name())
    }
    fn schema(map: &mut MetaMap) {
        map.entry(Self::type_name())
            .or_insert_with(|| Metadata::Vec(V::type_name()));
        if !map.contains_key(&V::type_name()) {
            Vec::<V>::schema(map)
        }
    }
}

impl IntoSchema for core::time::Duration {
    fn type_name() -> String {
        core::any::type_name::<Self>().to_owned()
    }
    // Look at:
    //   https://docs.rs/parity-scale-codec/2.1.1/src/parity_scale_codec/codec.rs.html#1182-1192
    fn schema(map: &mut MetaMap) {
        let _ = map.entry(Self::type_name()).or_insert_with(|| {
            Metadata::TupleStruct(UnnamedFieldsMeta {
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
            Metadata::Array(ArrayMeta {
                ty: T::type_name(),
                len: L.try_into().expect("usize should always fit in u64"),
            })
        });
        if !map.contains_key(&T::type_name()) {
            T::schema(map);
        }
    }
}

macro_rules! impl_schema_tuple {
    ($( ( $($id:ident),* ) ),* ) => {$(
        impl<$($id: IntoSchema),*> IntoSchema for ($($id),*) {
            fn type_name() -> String {
                format!("({})", vec![$($id::type_name()),*].join(", "))
            }

            fn schema(map: &mut MetaMap) {
                let _ = map.entry(Self::type_name()).or_insert_with(|| {
                    Metadata::TupleStruct(UnnamedFieldsMeta {
                        types: vec![$($id::type_name()),*],
                    })
                });
                $(
                if !map.contains_key(& $id::type_name()) {
                    $id::schema(map);
                }
                )*
            }
        }
    )*};
}

impl_schema_tuple!(
    (A0, A1),
    (A0, A1, A2),
    (A0, A1, A2, A3),
    (A0, A1, A2, A3, A4),
    (A0, A1, A2, A3, A4, A5),
    (A0, A1, A2, A3, A4, A5, A6),
    (A0, A1, A2, A3, A4, A5, A6, A7),
    (A0, A1, A2, A3, A4, A5, A6, A7, A8),
    (A0, A1, A2, A3, A4, A5, A6, A7, A8, A9),
    (A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10)
);

pub mod prelude {
    //! Exports common types.

    pub use super::*;
}
