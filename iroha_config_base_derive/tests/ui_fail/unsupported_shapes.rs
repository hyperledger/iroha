use iroha_config_base::ReadConfig;

#[derive(ReadConfig)]
struct Test1;

#[derive(ReadConfig)]
struct Test2(u64); // newtype

#[derive(ReadConfig)]
struct Test3(u64, u32); // unnamed

#[derive(ReadConfig)]
enum Test4 {
    One,
}

pub fn main() {}
