use iroha_config_base::ReadConfig;

#[derive(ReadConfig)]
struct Test<T> {
    foo: T,
}

pub fn main() {}
