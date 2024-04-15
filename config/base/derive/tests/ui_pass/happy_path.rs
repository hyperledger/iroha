use std::convert::Infallible;

use iroha_config_base::{
    read::{CustomEnvFetcher, CustomEnvRead, CustomEnvReadError},
    ReadConfig, WithOrigin,
};

#[derive(ReadConfig)]
struct Test {
    required: u64,
    required_with_origin: WithOrigin<u64>,
    optional: Option<u64>,
    optional_with_origin: Option<WithOrigin<u64>>,
    #[config(default)]
    with_default: bool,
    #[config(default = "true")]
    with_default_expr: bool,
    #[config(env = "FROM_ENV")]
    from_env: String,
    #[config(nested)]
    nested: Nested,
    #[config(env = "TEST", default = "true")]
    with_default_expr_and_env: bool,
    #[config(env_custom)]
    foo_bar: FooBar,
}

#[derive(ReadConfig)]
struct Nested {
    foo: Option<u32>,
}

#[derive(serde::Deserialize)]
struct FooBar(u32);

impl CustomEnvRead for FooBar {
    type Context = Infallible;

    fn read(
        _fetcher: &mut CustomEnvFetcher,
    ) -> Result<Option<Self>, CustomEnvReadError<Self::Context>> {
        todo!();
    }
}

pub fn main() {}
