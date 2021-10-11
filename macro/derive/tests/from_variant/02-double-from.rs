include!("01-big-enum.rs");

impl std::convert::From<Variant1> for Enum {
    fn from(variant: Variant1) -> Self {
        Self::Variant1(variant)
    }
}
