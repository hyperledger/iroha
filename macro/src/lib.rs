//! Crate containing iroha macros

#![allow(clippy::module_name_repetitions)]

pub use iroha_derive::*;

/// Crate with errors
pub mod error {
    use std::{any::type_name, error, fmt, marker::PhantomData};

    pub use eyre::*;

    /// Error which happens if `TryFrom` from enum variant fails
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
