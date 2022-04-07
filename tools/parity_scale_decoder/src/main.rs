#![allow(clippy::print_stdout, clippy::use_debug, clippy::unnecessary_wraps)]

use std::{fs, io, path::PathBuf};

use clap::Parser;
use eyre::{eyre, Result};
use iroha_macro::DumpDecodedMap;

/// Parity Scale decoder tool for Iroha structs
#[derive(Debug, Parser)]
#[clap(version, about, author)]
struct Args {
    /// Path to the binary with encoded Iroha structure
    binary: PathBuf,
    /// Type that is expected to be encoded in binary.
    /// If not specified then a guess will be attempted
    #[clap(short, long = "type")]
    type_id: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let bytes = fs::read(args.binary)?;
    let stdout = io::stdout();
    let mut writer = io::BufWriter::new(stdout.lock());

    let map = DumpDecodedMap::new(); //iroha_macro::get_dump_decoded_map!();

    if let Some(type_id) = args.type_id {
        return decode_by_type(&map, &type_id, &bytes, &mut writer);
    }

    decode_by_guess(&map, &bytes, &mut writer)
}

fn decode_by_type<W: io::Write>(
    map: &DumpDecodedMap,
    type_id: &str,
    bytes: &[u8],
    writer: &mut W,
) -> Result<()> {
    map.get(type_id).map_or_else(
        || Err(eyre!("Unknown type: `{type_id}`")),
        |f| f(bytes, writer),
    )
}

fn decode_by_guess<W: io::Write>(map: &DumpDecodedMap, bytes: &[u8], writer: &mut W) -> Result<()> {
    let count = map.values().filter_map(|f| f(bytes, writer).ok()).count();
    if count == 0 {
        return Err(eyre!("No compatible types found"));
    }
    writeln!(writer, "\nFound {count} compatible types").map_err(Into::into)
}
