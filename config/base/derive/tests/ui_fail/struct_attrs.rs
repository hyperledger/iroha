use iroha_config_base::ReadConfig;

#[derive(ReadConfig)]
#[config(whatever, a, b, c)]
struct Test {
    foo: u64,
}

pub fn main() {}
