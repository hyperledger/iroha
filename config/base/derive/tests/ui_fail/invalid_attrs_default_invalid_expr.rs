use iroha_config_base::ReadConfig;

#[derive(ReadConfig)]
struct Test {
    #[config(default = "not an expression I guess")]
    foo: u64,
}

pub fn main() {}
