use iroha_config_base::ReadConfig;

#[derive(ReadConfig)]
struct Test {
    #[config(,,,)]
    foo: u64,
}

pub fn main() {}
