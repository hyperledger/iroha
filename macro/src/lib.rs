//! Crate containing iroha macros

#![allow(clippy::module_name_repetitions)]
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

#[cfg(feature = "dump_decoded")]
pub use dump_decoded::*;

#[cfg(feature = "dump_decoded")]
mod dump_decoded {
    use std::{collections::BTreeMap, fmt::Debug, io::Write};

    pub use eyre;
    pub use once_cell;
    use parity_scale_codec::Decode;

    /// Function pointer to [`DumpDecoded::dump_decoded()`]
    ///
    /// Function pointer is used cause trait object can not be used
    /// due to [`Sized`] bound in [`Decode`] trait
    pub type DumpDecodedPtr = fn(&[u8], &mut dyn Write) -> Result<(), eyre::Error>;

    /// Map (Type Name -> `dump_decode()` ptr)
    pub type DumpDecodedMap = BTreeMap<String, DumpDecodedPtr>;

    /// Types implementing this trait can be decoded from bytes
    /// with *Parity Scale Codec* and dumped to something implementing [`Write`]
    pub trait DumpDecoded: Debug + Decode {
        /// Decode `Self` from `input` and dump to `w`
        ///
        /// # Errors
        /// - If decoding from *Parity Scale Codec* fails
        /// - If writing into `w` fails
        fn dump_decoded(mut input: &[u8], w: &mut dyn Write) -> Result<(), eyre::Error> {
            let obj = <Self as Decode>::decode(&mut input)?;
            #[allow(clippy::use_debug)]
            writeln!(w, "{:#?}", obj)?;
            Ok(())
        }
    }
}
