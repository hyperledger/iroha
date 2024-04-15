use iroha_config_base::ReadConfig;

#[derive(ReadConfig)]
struct Test {
    #[config(nested, env_custom)]
    foo: u64,
}

#[derive(ReadConfig)]
struct Test2 {
    #[config(default, nested)]
    foo: u64,
}

#[derive(ReadConfig)]
struct Test3 {
    #[config(env = "FASDF", env_custom)]
    foo: u64,
}

pub fn main() {}
