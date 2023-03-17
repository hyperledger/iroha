//! Some primitive utils for derive macros.

pub mod params;

/// Parse `input` as one of the listed keywords mapping it to the enum variants.
///
/// # Example
///
/// ```no_run
/// mod kw {
///     pub mod variants {
///         syn::custom_keyword!(foo);
///         syn::custom_keyword!(bar);
///     }
/// }
///
/// enum Variant {
///     Foo,
///     Bar,
/// }
///
/// impl syn::parse::Parse for Variant {
///     fn parse(input: syn::parse::ParseStream) -> syn::parse::Result<Self> {
///         use kw::variants::*;
///
///         iroha_derive_primitives::parse_keywords!(input,
///             foo => Variant::Foo,
///             bar => Variant::Bar,
///         )
///     }
/// }
/// ```
#[macro_export]
macro_rules! parse_keywords {
    ($input:ident, $($kw:path => $var:expr),+ $(,)?) => {
        $(
            if $input.parse::<$kw>().is_ok() {
                Ok($var)
            } else
        )+
        {Err($input.error(format!("expected one of: {}", stringify!($($kw),+))))}
    };
}
