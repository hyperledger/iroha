//! Contains traits that is needed for macro implementation

#[cfg(feature = "dump_decoded")]
pub use dump_decoded::*;

#[cfg(feature = "dump_decoded")]
mod dump_decoded {
    use std::{collections::HashMap, fmt::Debug, io::Write};

    pub use eyre;
    pub use once_cell;
    use parity_scale_codec::Decode;

    /// Function pointer to [`DumpDecoded::dump_decoded()`]
    ///
    /// Function pointer is used cause trait object can not be used
    /// due to [`Sized`] bound in [`Decode`] trait
    pub type DumpDecodedPtr = fn(&[u8], &mut dyn Write) -> Result<(), eyre::Error>;

    /// Map (Type Name -> `dump_decode()` ptr)
    pub type DumpDecodedMap = HashMap<String, DumpDecodedPtr>;

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
