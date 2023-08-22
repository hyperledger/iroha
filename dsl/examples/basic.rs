extern crate iroha_dsl;
extern crate iroha_data_model;
use iroha_dsl::expr;
use iroha_data_model::{prelude::*};

fn main() {
    assert_eq!(expr!(54654*5 + 1), Add::new(Multiply::new(54654_u64, 5_u64), 1_u64));
    // println!("{}", expr!(not true and false));
    // println!("{}", expr!(if 4 = 4 then 64 else 32));
    println!("{}", expr!(register "bucket"));
    println!("{}", expr!(register "beans@bucket"));
}
