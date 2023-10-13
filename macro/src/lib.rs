//! Crate containing iroha macros
#![cfg_attr(not(feature = "std"), no_std)]

pub use iroha_derive::*;

/// Crate with errors
pub mod error {
    use core::{any::type_name, fmt, marker::PhantomData};

    /// Error which happens if `TryFrom` from enum variant fails
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub struct ErrorTryFromEnum<F, T> {
        from: PhantomData<F>,
        to: PhantomData<T>,
    }

    #[cfg(feature = "std")]
    impl<F, T> std::error::Error for ErrorTryFromEnum<F, T> {}

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
                from: PhantomData,
                to: PhantomData,
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
