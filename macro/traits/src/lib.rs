//! Contains traits that is needed for macro implementation

#[cfg(feature = "dump_decoded")]
use std::fmt::Debug;
use std::io::Write;

#[cfg(feature = "dump_decoded")]
use parity_scale_codec::Decode;

/// Types implementing this trait can be decoded from bytes
/// with *Parity Scale Codec* and dumped to something implementing [`Write`]
#[cfg(feature = "dump_decoded")]
pub trait DumpDecoded: Debug + Decode {
    /// Decode `Self` from `input` and dump to `w`
    ///
    /// # Errors
    /// - If decoding from *Parity Scale Codec* fails
    /// - If writing into `w` fails
    fn dump_decoded(mut input: &[u8], w: &mut dyn Write) -> Result<(), eyre::Error> {
        let obj = <Self as Decode>::decode(&mut input)?;
        #[allow(clippy::use_debug)]
        writeln!(w, "{:?}", obj)?;
        Ok(())
    }
}
