use manyhow::{error_message, Result};
use proc_macro2::TokenStream;
use quote::quote;

pub fn numeric_impl(input: TokenStream) -> Result<TokenStream> {
    let input = input.to_string();
    let numeric = input
        .parse::<::iroha_numeric::Numeric>()
        .map_err(|err| error_message!("failed to parse numeric: {err}"))?;
    let mantissa = numeric.mantissa();
    let scale = numeric.scale();

    Ok(quote! {
        Numeric::new(#mantissa, #scale)
    })
}
