//! A wrapper type around [`manyhow::Emitter`] that provides a more ergonomic API.

use drop_bomb::DropBomb;
use manyhow::ToTokensError;
use proc_macro2::TokenStream;

/// A wrapper type around [`manyhow::Emitter`] that provides a more ergonomic API.
///
/// This type is used to accumulate errors during parsing and code generation.
///
/// NOTE: you must call [`Emitter::finish`] or similar function to consume the accumulated errors.
/// `Emitter` will panic if dropped without consuming the errors.
pub struct Emitter {
    inner: manyhow::Emitter,
    bomb: DropBomb,
}

impl Emitter {
    /// Creates a new emitter. It must be consumed by calling any of the `finish_*` functions before dropping or it will panic.
    pub fn new() -> Self {
        Self {
            inner: manyhow::Emitter::new(),
            bomb: DropBomb::new("Emitter dropped without consuming accumulated errors"),
        }
    }

    /// Add a new error to the emitter.
    pub fn emit<E: ToTokensError + 'static>(&mut self, err: E) {
        self.inner.emit(err);
    }

    /// Handle a [`manyhow::Result`] by either returning the value or emitting the error.
    ///
    /// If the passed value is `Err`, the error will be emitted and `None` will be returned.
    pub fn handle<E: ToTokensError + 'static, T>(
        &mut self,
        result: manyhow::Result<T, E>,
    ) -> Option<T> {
        match result {
            Ok(value) => Some(value),
            Err(err) => {
                self.emit(err);
                None
            }
        }
    }

    /// Same as [`Emitter::handle`], but returns the default value of `T` if the passed value is `Err`.
    #[allow(unused)]
    pub fn handle_or_default<E: ToTokensError + 'static, T: Default>(
        &mut self,
        result: manyhow::Result<T, E>,
    ) -> T {
        self.handle(result).unwrap_or_default()
    }

    /// Consume the emitter, returning a [`manyhow::Error`] if any errors were emitted.
    ///
    /// # Errors
    ///
    /// This function returns an error if the emitter has some errors accumulated.
    pub fn finish(mut self) -> manyhow::Result<()> {
        self.bomb.defuse();
        self.inner.into_result()
    }

    /// Same as [`Emitter::finish`], but returns the given value if no errors were emitted.
    ///
    /// # Errors
    ///
    /// This function returns an error if the emitter has some errors accumulated.
    #[allow(unused)]
    pub fn finish_with<T>(self, result: T) -> manyhow::Result<T> {
        self.finish().map(|_| result)
    }

    /// Handles the given [`manyhow::Result`] and consumes the emitter.
    ///
    /// # Errors
    ///
    /// This function returns an error if:
    /// - The given result is `Err`
    /// - The emitter has some errors accumulated
    #[allow(unused)]
    pub fn finish_and<E: ToTokensError + 'static, T>(
        mut self,
        result: manyhow::Result<T, E>,
    ) -> manyhow::Result<T> {
        match result {
            Ok(value) => self.finish_with(value),
            Err(err) => {
                self.emit(err);
                Err(self.finish().unwrap_err())
            }
        }
    }

    /// Consume the emitter, convert all errors into a token stream and append it to the given token stream.
    pub fn finish_to_token_stream(self, tokens: &mut TokenStream) {
        match self.finish() {
            Ok(()) => {}
            Err(e) => e.to_tokens(tokens),
        }
    }

    /// Consume the emitter, convert all errors into a token stream.
    pub fn finish_token_stream(self) -> TokenStream {
        let mut tokens_stream = TokenStream::new();
        self.finish_to_token_stream(&mut tokens_stream);
        tokens_stream
    }

    /// Consume the emitter, convert all errors into a token stream and append it to the given token stream.
    ///
    /// This function is useful when you want to handle errors in a macro, but want to emit some tokens even in case of an error.
    pub fn finish_token_stream_with(self, mut tokens_stream: TokenStream) -> TokenStream {
        self.finish_to_token_stream(&mut tokens_stream);
        tokens_stream
    }
}

impl Default for Emitter {
    fn default() -> Self {
        Self::new()
    }
}

impl<E: ToTokensError + 'static> Extend<E> for Emitter {
    fn extend<T: IntoIterator<Item = E>>(&mut self, iter: T) {
        self.inner.extend(iter)
    }
}
