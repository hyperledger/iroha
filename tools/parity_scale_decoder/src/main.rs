//! Parity Scale decoder tool for Iroha data types. For usage run with `--help`

#![allow(clippy::print_stdout, clippy::use_debug, clippy::unnecessary_wraps)]

use std::{collections::BTreeMap, fmt::Debug, fs, io, path::PathBuf};

use clap::Parser;
use colored::*;
use eyre::{eyre, Result};
use parity_scale_codec::Decode;

mod generate_map;
use generate_map::generate_map;

/// Parity Scale decoder tool for Iroha data types
#[derive(Debug, Parser)]
#[clap(version, about, author)]
enum Args {
    /// Show all available types
    ListTypes,
    /// Decode type from binary
    Decode(DecodeArgs),
}

#[derive(Debug, clap::Args)]
struct DecodeArgs {
    /// Path to the binary with encoded Iroha structure
    binary: PathBuf,
    /// Type that is expected to be encoded in binary.
    /// If not specified then a guess will be attempted
    #[clap(short, long = "type")]
    type_id: Option<String>,
}

/// Function pointer to [`DumpDecoded::dump_decoded()`]
///
/// Function pointer is used cause trait object can not be used
/// due to [`Sized`] bound in [`Decode`] trait
pub type DumpDecodedPtr = fn(&[u8], &mut dyn io::Write) -> Result<(), eyre::Error>;

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
    fn dump_decoded(mut input: &[u8], w: &mut dyn io::Write) -> Result<(), eyre::Error> {
        let obj = <Self as Decode>::decode(&mut input)?;
        #[allow(clippy::use_debug)]
        writeln!(w, "{:#?}", obj)?;
        Ok(())
    }
}

impl<T: Debug + Decode> DumpDecoded for T {}

fn main() -> Result<()> {
    let args = Args::parse();

    let map = generate_map();
    let stdout = io::stdout();
    let mut writer = io::BufWriter::new(stdout.lock());

    match args {
        Args::Decode(decode_args) => {
            let decoder = Decoder::new(decode_args, &map);
            decoder.decode(&mut writer)
        }
        Args::ListTypes => list_types(&map, &mut writer),
    }
}

/// Type decoder
struct Decoder<'map> {
    args: DecodeArgs,
    map: &'map DumpDecodedMap,
}

impl<'map> Decoder<'map> {
    /// Create new `Decoder` with `args` and `map`
    pub fn new(args: DecodeArgs, map: &'map DumpDecodedMap) -> Self {
        Self { args, map }
    }

    /// Decode type and print to `writer`
    pub fn decode<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        let bytes = fs::read(self.args.binary.clone())?;

        if let Some(type_id) = &self.args.type_id {
            return self.decode_by_type(type_id, &bytes, writer);
        }
        self.decode_by_guess(&bytes, writer)
    }

    /// Decode concrete `type` from `bytes` and print to `writer`
    fn decode_by_type<W: io::Write>(
        &self,
        type_id: &str,
        bytes: &[u8],
        writer: &mut W,
    ) -> Result<()> {
        self.map.get(type_id).map_or_else(
            || Err(eyre!("Unknown type: `{type_id}`")),
            |dump_decoded| dump_decoded(bytes, writer),
        )
    }

    /// Try to decode every type from `bytes` and print to `writer`
    ///
    /// TODO: Can be parallelized when there will be too many types
    fn decode_by_guess<W: io::Write>(&self, bytes: &[u8], writer: &mut W) -> Result<()> {
        let count = self
            .map
            .iter()
            .filter_map(|(type_name, dump_decoded)| {
                let mut buf = vec![0_u8; 1024];
                dump_decoded(bytes, &mut buf)
                    .ok()
                    .and_then(|_| String::from_utf8(buf).ok())
                    .and_then(|formatted| {
                        writeln!(writer, "{}:\n{}", type_name.italic().cyan(), formatted).ok()
                    })
            })
            .count();
        match count {
            0 => writeln!(writer, "No compatible types found"),
            1 => writeln!(writer, "{} compatible type found", "1".bold()),
            n => writeln!(writer, "{} compatible types found", n.to_string().bold()),
        }
        .map_err(Into::into)
    }
}

/// Print all supported types from `map` to `writer`
fn list_types<W: io::Write>(map: &DumpDecodedMap, writer: &mut W) -> Result<()> {
    for key in map.keys() {
        writeln!(writer, "{key}")?;
    }
    if !map.is_empty() {
        writeln!(writer)?;
    }

    match map.len() {
        0 => writeln!(writer, "No type is supported"),
        1 => writeln!(writer, "{} type is supported", "1".bold()),
        n => writeln!(writer, "{} types are supported", n.to_string().bold()),
    }
    .map_err(Into::into)
}
