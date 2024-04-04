use iroha_config_base::ReadConfig;

#[derive(ReadConfig)]
struct Test {
    #[config(nested, env_only)]
    nested: Nested,
}

#[derive(ReadConfig)]
struct Nested {
    foo: Option<bool>,
}

pub fn main() {}
