trait Predicate {}

#[derive(iroha_actor::Message)]
#[message(result = "i32")]
struct M<A: Predicate>(A);

fn main() {}
