use alloc::collections::BTreeMap;
use core::any::TypeId;

use serde::ser::*;

use crate::*;

trait AddContext {
    fn add_ctx<'ctx>(&self, context: &'ctx MetaMap) -> WithContext<'ctx, '_, Self> {
        WithContext {
            context,
            data: self,
        }
    }
}

impl<T: ?Sized> AddContext for T {}

struct WithContext<'ctx, 'a, T: ?Sized> {
    context: &'ctx MetaMap,
    data: &'a T,
}

impl<T: ?Sized> WithContext<'_, '_, T> {
    fn type_name(&self, type_id: TypeId) -> &String {
        &self
            .context
            .0
            .get(&type_id)
            .unwrap_or_else(|| panic!("Failed to find type id `{:?}`", type_id))
            .0
    }
}

impl Serialize for WithContext<'_, '_, ArrayMeta> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("type", self.type_name(self.data.ty))?;
        map.serialize_entry("len", &self.data.len)?;
        map.end()
    }
}
impl PartialEq for WithContext<'_, '_, ArrayMeta> {
    fn eq(&self, other: &Self) -> bool {
        self.type_name(self.data.ty) == other.type_name(other.data.ty)
            && self.data.len == other.data.len
    }
}

impl Serialize for WithContext<'_, '_, VecMeta> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.type_name(self.data.ty))
    }
}
impl PartialEq for WithContext<'_, '_, VecMeta> {
    fn eq(&self, other: &Self) -> bool {
        self.type_name(self.data.ty) == other.type_name(other.data.ty)
    }
}

impl Serialize for WithContext<'_, '_, Declaration> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("name", &self.data.name)?;
        map.serialize_entry("type", self.type_name(self.data.ty))?;
        map.end()
    }
}
impl PartialEq for WithContext<'_, '_, Declaration> {
    fn eq(&self, other: &Self) -> bool {
        self.data.name == other.data.name
            && self.type_name(self.data.ty) == other.type_name(other.data.ty)
    }
}
impl Serialize for WithContext<'_, '_, NamedFieldsMeta> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.data.declarations.len()))?;

        for declaration in &self.data.declarations {
            seq.serialize_element(&declaration.add_ctx(self.context))?;
        }

        seq.end()
    }
}
impl PartialEq for WithContext<'_, '_, NamedFieldsMeta> {
    fn eq(&self, other: &Self) -> bool {
        self.data.declarations == other.data.declarations
    }
}

impl Serialize for WithContext<'_, '_, UnnamedFieldsMeta> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_tuple(self.data.types.len())?;

        for &type_id in &self.data.types {
            seq.serialize_element(self.type_name(type_id))?;
        }

        seq.end()
    }
}
impl PartialEq for WithContext<'_, '_, UnnamedFieldsMeta> {
    fn eq(&self, other: &Self) -> bool {
        if self.data.types.len() != other.data.types.len() {
            return false;
        }

        self.data
            .types
            .iter()
            .zip(other.data.types.iter())
            .all(|(&self_type, &other_type)| {
                self.type_name(self_type) == other.type_name(other_type)
            })
    }
}

impl Serialize for WithContext<'_, '_, EnumMeta> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.data.variants.len()))?;

        for variant in &self.data.variants {
            seq.serialize_element(&variant.add_ctx(self.context))?;
        }

        seq.end()
    }
}
impl PartialEq for WithContext<'_, '_, EnumMeta> {
    fn eq(&self, other: &Self) -> bool {
        self.data
            .variants
            .iter()
            .zip(other.data.variants.iter())
            .all(|(self_variant, other_variant)| {
                self_variant.add_ctx(self.context) == other_variant.add_ctx(other.context)
            })
    }
}

impl Serialize for WithContext<'_, '_, EnumVariant> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if let Some(type_id) = self.data.ty {
            let mut map = serializer.serialize_map(Some(3))?;
            map.serialize_entry("tag", &self.data.tag)?;
            map.serialize_entry("discriminant", &self.data.discriminant)?;
            map.serialize_entry("type", self.type_name(type_id))?;
            map.end()
        } else {
            let mut map = serializer.serialize_map(Some(2))?;
            map.serialize_entry("tag", &self.data.tag)?;
            map.serialize_entry("discriminant", &self.data.discriminant)?;
            map.end()
        }
    }
}
impl PartialEq for WithContext<'_, '_, EnumVariant> {
    fn eq(&self, other: &Self) -> bool {
        if !match (self.data.ty, other.data.ty) {
            (Some(self_ty), Some(other_ty)) => self.type_name(self_ty) == other.type_name(other_ty),
            (None, None) => true,
            _ => false,
        } {
            return false;
        }

        self.data.tag == other.data.tag
    }
}

impl Serialize for WithContext<'_, '_, ResultMeta> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("ok", self.type_name(self.data.ok))?;
        map.serialize_entry("err", self.type_name(self.data.err))?;
        map.end()
    }
}
impl PartialEq for WithContext<'_, '_, ResultMeta> {
    fn eq(&self, other: &Self) -> bool {
        self.type_name(self.data.ok) == other.type_name(other.data.ok)
            && self.type_name(self.data.err) == other.type_name(other.data.err)
    }
}

impl Serialize for WithContext<'_, '_, MapMeta> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("key", self.type_name(self.data.key))?;
        map.serialize_entry("value", self.type_name(self.data.value))?;
        map.end()
    }
}
impl PartialEq for WithContext<'_, '_, MapMeta> {
    fn eq(&self, other: &Self) -> bool {
        self.type_name(self.data.key) == other.type_name(other.data.key)
            && self.type_name(self.data.value) == other.type_name(other.data.value)
    }
}

impl Serialize for WithContext<'_, '_, FixedMeta> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("base", self.type_name(self.data.base))?;
        map.serialize_entry("decimal_places", &self.data.decimal_places)?;
        map.end()
    }
}
impl PartialEq for WithContext<'_, '_, FixedMeta> {
    fn eq(&self, other: &Self) -> bool {
        self.data.decimal_places == other.data.decimal_places
            && self.type_name(self.data.base) == other.type_name(other.data.base)
    }
}

impl Serialize for WithContext<'_, '_, Metadata> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        macro_rules! match_variants {
            ( $($variant:ident),+ ) => {
                match self.data {
                    Metadata::String => serializer.serialize_str(self.type_name(TypeId::of::<String>())),
                    Metadata::Bool => serializer.serialize_str(self.type_name(TypeId::of::<bool>())),
                    Metadata::Option(type_id) => {
                        let mut map = serializer.serialize_map(Some(1))?;
                        map.serialize_entry("Option", self.type_name(*type_id))?;
                        map.end()
                    }
                    Metadata::Int(int_mode) => {
                        let mut map = serializer.serialize_map(Some(1))?;
                        map.serialize_entry("Int", int_mode)?;
                        map.end()
                    }
                    Metadata::Tuple(tuple) => {
                        let name = "Tuple";

                        match tuple.types[..] {
                            [] => serializer.serialize_unit_struct(name),
                            [type_id] => serializer.serialize_newtype_struct(name, self.type_name(type_id)),
                            _ => {
                                let mut map = serializer.serialize_map(Some(1))?;
                                map.serialize_entry(name, &tuple.add_ctx(&self.context))?;
                                map.end()
                            }
                        }
                    } $(
                    Metadata::$variant(type_) => {
                        let mut map = serializer.serialize_map(Some(1))?;
                        map.serialize_entry(stringify!($variant), &type_.add_ctx(&self.context))?;
                        map.end()
                    })+
                }
            };
        }

        match_variants!(Struct, Enum, FixedPoint, Array, Vec, Map, Result)
    }
}
impl PartialEq for WithContext<'_, '_, Metadata> {
    fn eq(&self, other: &Self) -> bool {
        macro_rules! match_variants {
            ( $($variant:ident),+ ) => {
                match self.data {
                    Metadata::String => matches!(other.data, Metadata::String),
                    Metadata::Bool => matches!(other.data, Metadata::Bool),
                    Metadata::Int(self_meta) => {
                        if let Metadata::Int(other_meta) = other.data {
                            return self_meta == other_meta
                        }

                        false
                    }
                    Metadata::Option(self_type_id) => {
                        if let Metadata::Option(other_type_id) = other.data {
                            return self.type_name(*self_type_id) == other.type_name(*other_type_id)
                        }

                        false
                    } $(
                    Metadata::$variant(self_type) => {
                        if let Metadata::$variant(other_type) = other.data {
                            return self_type.add_ctx(&self.context) == other_type.add_ctx(&self.context);
                        }

                        false
                    })+
                }
            };
        }

        match_variants!(Tuple, Struct, Enum, FixedPoint, Array, Vec, Map, Result)
    }
}

impl Serialize for MetaMap {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut duplicates = BTreeMap::new();

        let mut sorted_map = BTreeMap::new();
        for (type_name, schema) in self.0.values() {
            if let Some(duplicate) = sorted_map.insert(type_name, schema) {
                // NOTE: It's ok to serialize two types to the same name if they
                // are represented by the same schema, i.e. for transparent types
                if schema.add_ctx(self) != duplicate.add_ctx(self) {
                    duplicates
                        .entry(type_name)
                        .or_insert_with(|| vec![duplicate])
                        .push(schema);
                }
            }
        }

        assert!(
            duplicates.is_empty(),
            "Duplicate type names: {duplicates:#?}"
        );

        let mut map = serializer.serialize_map(Some(sorted_map.len()))?;
        for (type_name, schema) in &sorted_map {
            map.serialize_entry(type_name, &(*schema).add_ctx(self))?;
        }

        map.end()
    }
}
