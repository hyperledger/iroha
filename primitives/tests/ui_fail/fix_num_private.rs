use iroha_primitives::fixed::{Fixed, FixNum};

fn main() {
    let quantity = Fixed(FixNum::try_from(-123.45_f64).unwrap());
}
