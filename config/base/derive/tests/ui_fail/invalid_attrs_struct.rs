use iroha_config_base::ReadConfig;

#[derive(ReadConfig)]
#[config(whatever)] // not supported on structs
struct Test1 {
    foo: u64,
}

pub fn main() {}
