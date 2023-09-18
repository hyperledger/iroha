use iroha_data_model_derive::HasOrigin;

#[derive(HasOrigin)]
#[has_origin(origin = Object)]
#[has_origin(origin = Object)]
#[has_origin(origin = Object)]
enum MultipleAttributes {}

fn main() {}
