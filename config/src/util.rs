macro_rules! impl_serialize_display {
    ($ty:ty) => {
        impl serde::Serialize for $ty {
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.collect_str(self)
            }
        }
    };
}

macro_rules! impl_deserialize_from_str {
    ($ty:ty) => {
        impl<'de> serde::Deserialize<'de> for $ty {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                String::deserialize(deserializer)?
                    .parse()
                    .map_err(serde::de::Error::custom)
            }
        }
    };
}

pub(crate) use impl_deserialize_from_str;
pub(crate) use impl_serialize_display;
