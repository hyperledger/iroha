//! Crate containing iroha macroses

#![allow(clippy::doc_markdown, clippy::module_name_repetitions)]

/// Crate with errors
pub mod error {
    pub use iroha_error::*;
    use std::{any::type_name, error, fmt, marker::PhantomData};

    /// Error which happens if TryFrom from enum variant fails
    #[derive(Clone, Copy, Eq, PartialEq)]
    pub struct ErrorTryFromEnum<F, T> {
        from: PhantomData<F>,
        to: PhantomData<T>,
    }

    impl<F, T> error::Error for ErrorTryFromEnum<F, T> {}
    impl<F, T> fmt::Debug for ErrorTryFromEnum<F, T> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "ErrorTryFromEnum<{}, {}>",
                type_name::<F>(),
                type_name::<T>()
            )
        }
    }
    impl<F, T> Default for ErrorTryFromEnum<F, T> {
        fn default() -> Self {
            Self {
                from: PhantomData::default(),
                to: PhantomData::default(),
            }
        }
    }

    impl<F, T> fmt::Display for ErrorTryFromEnum<F, T> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "Failed converting from {} to {}",
                type_name::<F>(),
                type_name::<T>()
            )
        }
    }
}

/// Trait alias for encode + decode
pub trait Io: parity_scale_codec::Encode + parity_scale_codec::Decode {}
/// Derive macro trait
pub trait IntoContract {}
/// Derive macro trait
pub trait IntoQuery {}
