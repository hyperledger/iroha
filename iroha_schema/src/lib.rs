//! Module for schematizing rust types in other languages for translation.

use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

/// Derive schema. It will make your structure schemaable
pub use iroha_schema_derive::IntoSchema;
use serde::Serialize;

/// Metadata map
pub type MetaMap = BTreeMap<String, Metadata>;

/// `IntoSchema` trait
pub trait IntoSchema {
    /// Returns unique type name.
    /// WARN: `std::any::type_name` is compiler related, so is not unique.
    /// I guess we should change it somehow later
    fn type_name() -> String {
        let mut name = module_path!().to_owned();
        name.push_str("::");
        name.push_str(std::any::type_name::<Self>());
        name
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

/// Metadata
#[derive(Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Clone)]
pub enum Metadata {
    /// Structure with named fields
    Struct(NamedFieldsMeta),
    /// Unnamed structure
    TupleStruct(UnnamedFieldsMeta),
    /// Enum
    Enum(EnumMeta),
    /// Integer
    Int(IntMode),
    /// String
    String,
    /// Bool
    Bool,
    /// Array
    Array(ArrayMeta),
    /// Vector with type
    Vec(String),
    /// Option with type
    Option(String),
    /// Map
    Map(MapMeta),
    /// Result
    Result(ResultMeta),
}

/// Array metadata
#[derive(Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Clone)]
pub struct ArrayMeta {
    ty: String,
    len: usize,
}

/// Named fields
#[derive(Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Clone)]
pub struct NamedFieldsMeta {
    /// Fields
    pub declarations: Vec<Declaration>,
    //todo add collection of properties meta defined in struct
}

/// Field
#[derive(Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Clone)]
pub struct Declaration {
    /// Field name
    pub name: String,
    /// Type
    pub ty: String,
}

/// Unnamed fileds
#[derive(Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Clone)]
pub struct UnnamedFieldsMeta {
    /// Field types
    pub types: Vec<String>,
    //todo add collection of properties meta defined in struct
}

/// Enum metadata
#[derive(Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Clone)]
pub struct EnumMeta {
    /// Enum variants
    pub variants: Vec<EnumVariant>,
}

/// Enum variant
#[derive(Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Clone)]
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
#[derive(Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Clone)]
pub struct ResultMeta {
    /// Ok type
    pub ok: String,
    /// Err type
    pub err: String,
}

/// Map variant
#[derive(Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Clone)]
pub struct MapMeta {
    /// Key type
    pub key: String,
    /// Value type
    pub value: String,
}

/// Integer mode
#[derive(Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Clone, Copy)]
pub enum IntMode {
    /// Fixed width
    FixedWidth,
    /// Scale compact
    Compact,
}

/// Compact predicate. Just for documentation purposes
#[derive(Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Clone, Copy)]
pub struct Compact<T>(T);

macro_rules! impl_schema_int {
    ($($t:ty,)*) => {$(
        impl IntoSchema for $t {
            fn type_name() -> String {
                std::any::type_name::<Self>().to_owned()
            }
            fn schema(map: &mut MetaMap) {
                let _ = map.entry(Self::type_name()).or_insert(
                    Metadata::Int(IntMode::FixedWidth),
                );
            }
        }

        impl IntoSchema for Compact<$t> {
            fn type_name() -> String {
                format!("iroha_schema::Compact<{}>", <$t as IntoSchema>::type_name())
            }
            fn schema(map: &mut MetaMap) {
                let _ = map.entry(Self::type_name()).or_insert(Metadata::Int(IntMode::Compact));
            }
        }
    )*};
}

impl_schema_int!(u128, u64, u32, u16, u8, i128, i64, i32, i16, i8,);

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
        std::any::type_name::<Self>().to_owned()
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
        Vec::<V>::schema(map)
    }
}

impl IntoSchema for Duration {
    fn type_name() -> String {
        std::any::type_name::<Self>().to_owned()
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
                len: L,
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
