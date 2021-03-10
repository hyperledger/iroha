#[derive(Debug, iroha_error_macro::Error)]
enum Error {
    #[error("This is A")]
    A,
}

fn main() {}
