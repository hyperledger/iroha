use std::{borrow::Borrow, collections::HashMap};

pub use http::{Method, Response, StatusCode};

/// Type alias for HTTP headers hash map
pub type Headers = HashMap<String, String>;

/// General trait for building http-requests.
///
/// To use custom builder with client, you need to implement this trait for some type and pass it
/// to the client that will fill it.
pub trait RequestBuilder {
    /// Constructs a new builder with provided method and URL
    #[must_use]
    fn new<U>(method: Method, url: U) -> Self
    where
        U: AsRef<str>;

    /// Sets request's body in bytes
    #[must_use]
    fn bytes(self, data: Vec<u8>) -> Self;

    /// Sets request's query params
    #[must_use]
    fn params<P, K, V>(self, params: P) -> Self
    where
        P: IntoIterator,
        P::Item: Borrow<(K, V)>,
        K: AsRef<str>,
        V: ToString;

    /// Sets request's headers
    #[must_use]
    fn headers(self, headers: Headers) -> Self;
}
