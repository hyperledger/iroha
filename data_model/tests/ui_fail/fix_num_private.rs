use iroha_data_model::fixed::{Fixed, FixNum};

fn main() {
    let quantity = Fixed(FixNum::try_from(-123.45_f64).unwrap());
}
