use std::fmt::Display;

#[derive(Debug)]
struct ErrorInner;

impl Display for ErrorInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "This is inner.")
    }
}

impl std::error::Error for ErrorInner {}

#[derive(Debug, iroha_error_macro::Error)]
enum Error {
    #[error("This is A")]
    A(#[source] ErrorInner),
}

#[test]
fn display_inner() {
    assert_eq!(
        Error::A(ErrorInner).to_string(),
        "This is A. Caused by: This is inner.".to_owned()
    )
}
