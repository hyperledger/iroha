use core::str::FromStr;

use manyhow::{error_message, Result};
use proc_macro2::TokenStream;
use quote::quote;

pub fn numeric_impl(input: TokenStream) -> Result<TokenStream> {
    let input = input.to_string();
    let numeric = ::iroha_numeric::Numeric::from_str(&input)
        .map_err(|err| error_message!("failed to parse numeric: {err}"))?;
    let mantissa = numeric.mantissa();
    let scale = numeric.scale();

    Ok(quote! {
        Numeric::new(#mantissa, #scale)
    })
}
