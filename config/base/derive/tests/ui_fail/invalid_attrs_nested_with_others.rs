use iroha_config_base::ReadConfig;

#[derive(ReadConfig)]
struct Test {
    #[config(nested, env_only)] // nested with other attrs
    nested: Nested,
}

#[derive(ReadConfig)]
struct Test2 {
    #[config(default, nested)] // nested with other attrs (different order)
    nested: Nested,
}

#[derive(ReadConfig)]
struct Nested {
    foo: Option<bool>,
}

pub fn main() {}
