use iroha_data_model::fixed::Fixed;

fn main() {
	let quantity = Fixed(iroha_data_model::fixed::FixNum::try_from(-123.45_f64).unwrap());
}
