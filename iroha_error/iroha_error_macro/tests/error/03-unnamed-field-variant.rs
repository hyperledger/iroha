#[derive(Debug, iroha_error_macro::Error)]
enum ErrorInner {
    #[error("This is A")]
    A,
    #[error("This is B")]
    B,
    #[error("This is C")]
    C,
}

#[derive(Debug, iroha_error_macro::Error)]
enum Error {
    #[error("This is A")]
    A(ErrorInner),
}

fn main() {}
