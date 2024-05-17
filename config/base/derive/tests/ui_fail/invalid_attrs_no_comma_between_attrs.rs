use iroha_config_base::ReadConfig;

#[derive(ReadConfig)]
struct Test {
    #[config(default env = "1234")]
    foo: u64,
}

pub fn main() {}
