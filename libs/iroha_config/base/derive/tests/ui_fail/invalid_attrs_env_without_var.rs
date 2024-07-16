use iroha_config_base::ReadConfig;

#[derive(ReadConfig)]
struct Test {
    #[config(env)] // without `= "VAR"`
    foo: u64,
}

pub fn main() {}
