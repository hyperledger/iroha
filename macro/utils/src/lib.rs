//! Module for various functions and structs to build macros in iroha.

mod emitter;

pub use emitter::Emitter;

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

/// Parses a single attribute of the form `#[attr_name(...)]` for darling using a `syn::parse::Parse` implementation.
///
/// If no attribute with specified name is found, returns `Ok(None)`.
pub fn parse_single_list_attr_opt<Body: syn2::parse::Parse>(
    attr_name: &str,
    attrs: &[syn2::Attribute],
) -> darling::Result<Option<Body>> {
    let mut accumulator = darling::error::Accumulator::default();

    // first, ensure there is only one attribute with the requested name
    // take the first one if there are multiple
    let matching_attrs = attrs
        .iter()
        .filter(|a| a.path().is_ident(attr_name))
        .collect::<Vec<_>>();
    let attr = match *matching_attrs.as_slice() {
        [] => {
            return accumulator.finish_with(None);
        }
        [attr] => attr,
        [attr, ref tail @ ..] => {
            // allow parsing to proceed further to collect more errors
            accumulator.push(
                darling::Error::custom(format!("Only one #[{}] attribute is allowed!", attr_name))
                    .with_span(
                        &tail
                            .iter()
                            .map(syn2::spanned::Spanned::span)
                            .reduce(|a, b| a.join(b).unwrap())
                            .unwrap(),
                    ),
            );
            attr
        }
    };

    let mut kind = None;

    match &attr.meta {
        syn2::Meta::Path(_) | syn2::Meta::NameValue(_) => accumulator.push(darling::Error::custom(
            format!("Expected #[{}(...)] attribute to be a list", attr_name),
        )),
        syn2::Meta::List(list) => {
            kind = accumulator.handle(syn2::parse2(list.tokens.clone()).map_err(Into::into));
        }
    }

    accumulator.finish_with(kind)
}

/// Parses a single attribute of the form `#[attr_name(...)]` for darling using a `syn::parse::Parse` implementation.
///
/// If no attribute with specified name is found, returns an error.
pub fn parse_single_list_attr<Body: syn2::parse::Parse>(
    attr_name: &str,
    attrs: &[syn2::Attribute],
) -> darling::Result<Body> {
    parse_single_list_attr_opt(attr_name, attrs)?
        .ok_or_else(|| darling::Error::custom(format!("Missing `#[{}(...)]` attribute", attr_name)))
}

/// Macro for automatic [`syn::parse::Parse`] impl generation for keyword
/// attribute structs in derive macros.
#[macro_export]
macro_rules! attr_struct2 {
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

        impl syn2::parse::Parse for $name {
            fn parse(input: syn2::parse::ParseStream) -> syn2::Result<Self> {
                Ok(Self {
                    $(
                        $field_name: input.parse()?,
                    )*
                })
            }
        }
    };
}
