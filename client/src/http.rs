use std::{borrow::Borrow, collections::HashMap};

use eyre::Result;
pub use http::{Method, Response, StatusCode};

/// Type alias for HTTP headers hash map
pub type Headers = HashMap<String, String>;

/// General trait for building http-requests.
///
/// To use custom builder with client, you need to implement this trait for some type and pass it
/// to the client that will fill it.
pub trait RequestBuilder {
    /// Used to create a builder itself
    ///
    /// # Errors
    /// May fail by some reason, depends on implementation
    fn build<U, P, K, V>(
        method: Method,
        url: U,
        body: Vec<u8>,
        query_params: P,
        headers: Headers,
    ) -> Result<Self>
    where
        U: AsRef<str>,
        P: IntoIterator,
        P::Item: Borrow<(K, V)>,
        K: AsRef<str>,
        V: ToString,
        Self: Sized;
}
