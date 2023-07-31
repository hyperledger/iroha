//! Module for various functions and structs to build macros in iroha.

/// Trait for attribute parsing generalization
pub trait AttrParser<Inner: syn::parse::Parse> {
    /// Attribute identifier `#[IDENT...]`
    const IDENT: &'static str;

    /// Parse `Inner` content of attribute
    ///
    /// # Errors
    /// - If `Inner` parsing failed
    /// - If `IDENT` doesn't match
    fn parse(attr: &syn::Attribute) -> syn::Result<Inner> {
        attr.path
            .is_ident(&<Self as AttrParser<_>>::IDENT)
            .then(|| attr.parse_args::<Inner>())
            .map_or_else(
                || {
                    Err(syn::parse::Error::new_spanned(
                        attr,
                        format!(
                            "Attribute must be in form #[{}...]",
                            <Self as AttrParser<_>>::IDENT
                        ),
                    ))
                },
                |inner| inner,
            )
    }
}

/// Macro for automatic [`syn::parse::Parse`] impl generation for keyword
/// attribute structs in derive macros.
#[macro_export]
macro_rules! attr_struct {
    // Matching struct with named fields
    (
        $( #[$meta:meta] )*
    //  ^~~~attributes~~~~^
        $vis:vis struct $name:ident {
            $(
                $( #[$field_meta:meta] )*
    //          ^~~~field attributes~~~!^
                $field_vis:vis $field_name:ident : $field_ty:ty
    //          ^~~~~~~~~~~~~~~~~a single field~~~~~~~~~~~~~~~^
            ),*
        $(,)? }
    ) => {
        $( #[$meta] )*
        $vis struct $name {
            $(
                $( #[$field_meta] )*
                $field_vis $field_name : $field_ty
            ),*
        }

        impl syn::parse::Parse for $name {
            fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
                Ok(Self {
                    $(
                        $field_name: input.parse()?,
                    )*
                })
            }
        }
    };
}
