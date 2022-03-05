include!("../ui_pass/enum_from_variant.rs");

impl From<Variant1> for Enum {
    fn from(variant: Variant1) -> Self {
        Self::Variant1(variant)
    }
}
