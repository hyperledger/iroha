//! Iroha DSL provides declarative API for Iroha Special Instructions,
//! Queries and other public functions.

#![warn(
    anonymous_parameters,
    missing_copy_implementations,
    missing_debug_implementations,
    missing_docs,
    rust_2018_idioms,
    private_doc_tests,
    trivial_casts,
    trivial_numeric_casts,
    unused,
    future_incompatible,
    nonstandard_style,
    unsafe_code,
    unused_import_braces,
    unused_results,
    variant_size_differences
)]

/// The prelude re-exports most commonly used traits, structs and macros from this crate.
pub mod prelude {
    #[doc(inline)]
    pub use iroha_data_model::prelude::*;
}

//TODO:
// - Try to get rid of Boxes in constructors arguments and without hacks like ::new(&Struct)

#[cfg(test)]
mod tests {
    use super::prelude::*;

    #[test]
    fn find_rate_and_make_exchange_isi_should_be_valid() {
        let _ = Pair::new(
            Transfer::<Asset, _, Asset>::new(
                AssetId::from_names("btc", "crypto", "seller", "company"),
                FindAssetQuantityById::new(AssetId::from_names(
                    "btc2eth_rate",
                    "exchange",
                    "dex",
                    "exchange",
                )),
                AssetId::from_names("btc", "crypto", "buyer", "company"),
            ),
            Transfer::<Asset, _, Asset>::new(
                AssetId::from_names("eth", "crypto", "buyer", "company"),
                FindAssetQuantityById::new(AssetId::from_names(
                    "btc2eth_rate",
                    "exchange",
                    "dex",
                    "exchange",
                )),
                AssetId::from_names("eth", "crypto", "seller", "company"),
            ),
        );
    }

    #[test]
    fn find_rate_and_check_it_greater_than_value_isi_should_be_valid() {
        let _ = If::new(
            Not::new(Greater::new(
                FindAssetQuantityById::new(AssetId::from_names(
                    "btc2eth_rate",
                    "exchange",
                    "dex",
                    "exchange",
                )),
                10,
            )),
            Fail::new("rate is less or equal to value"),
        );
    }

    struct FindRateAndCheckItGreaterThanValue {
        from_currency: String,
        to_currency: String,
        value: u32,
    }

    impl FindRateAndCheckItGreaterThanValue {
        pub fn new(from_currency: &str, to_currency: &str, value: u32) -> Self {
            FindRateAndCheckItGreaterThanValue {
                from_currency: from_currency.to_string(),
                to_currency: to_currency.to_string(),
                value,
            }
        }

        pub fn into_isi(self) -> If {
            If::new(
                Not::new(Greater::new(
                    FindAssetQuantityById::new(AssetId::from_names(
                        &format!("{}2{}_rate", self.from_currency, self.to_currency),
                        "exchange",
                        "dex",
                        "exchange",
                    )),
                    self.value,
                )),
                Fail::new("rate is less or equal to value"),
            )
        }
    }

    #[test]
    fn find_rate_and_check_it_greater_than_value_predefined_isi_should_be_valid() {
        let _ = FindRateAndCheckItGreaterThanValue::new("btc", "eth", 10).into_isi();
    }
}
