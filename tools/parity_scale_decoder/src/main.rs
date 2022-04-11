//! Parity Scale decoder tool for Iroha data types. For usage run with `--help`

#![allow(clippy::print_stdout, clippy::use_debug, clippy::unnecessary_wraps)]

use std::{fs, io, path::PathBuf};

use clap::Parser;
use eyre::{eyre, Result};
use iroha_data_model::prelude::*;
use iroha_macro::{get_dump_decoded_map, DumpDecodedMap};

/// Parity Scale decoder tool for Iroha data types
#[derive(Debug, Parser)]
#[clap(version, about, author)]
enum Args {
    /// Show all available types
    ListTypes,
    /// Decode type from binary
    Decode(Decode),
}

#[derive(Debug, clap::Args)]
struct Decode {
    /// Path to the binary with encoded Iroha structure
    binary: PathBuf,
    /// Type that is expected to be encoded in binary.
    /// If not specified then a guess will be attempted
    #[clap(short, long = "type")]
    type_id: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let map = get_dump_decoded_map!();
    let stdout = io::stdout();
    let mut writer = io::BufWriter::new(stdout.lock());

    match args {
        Args::Decode(decode_args) => decode(decode_args, map, &mut writer),
        Args::ListTypes => list_types(map, &mut writer),
    }
}

fn decode<W: io::Write>(args: Decode, map: &DumpDecodedMap, writer: &mut W) -> Result<()> {
    let bytes = fs::read(args.binary)?;

    if let Some(type_id) = args.type_id {
        return decode_by_type(map, &type_id, &bytes, writer);
    }
    decode_by_guess(map, &bytes, writer)
}

fn decode_by_type<W: io::Write>(
    map: &DumpDecodedMap,
    type_id: &str,
    bytes: &[u8],
    writer: &mut W,
) -> Result<()> {
    map.get(type_id).map_or_else(
        || Err(eyre!("Unknown type: `{type_id}`")),
        |dump_decoded| dump_decoded(bytes, writer),
    )
}

fn decode_by_guess<W: io::Write>(map: &DumpDecodedMap, bytes: &[u8], writer: &mut W) -> Result<()> {
    let count = map
        .values()
        .filter_map(|dump_decoded| {
            dump_decoded(bytes, writer)
                .ok()
                .and_then(|_| writeln!(writer).ok())
        })
        .count();
    match count {
        0 => writeln!(writer, "No compatible types found"),
        1 => writeln!(writer, "1 compatible type found"),
        n => writeln!(writer, "{n} compatible types found"),
    }
    .map_err(Into::into)
}

fn list_types<W: io::Write>(map: &DumpDecodedMap, writer: &mut W) -> Result<()> {
    for key in map.keys() {
        writeln!(writer, "{key}")?;
    }

    match map.len() {
        0 => writeln!(writer, "No type is supported"),
        1 => writeln!(writer, "\n1 type is supported"),
        n => writeln!(writer, "\n{n} types are supported"),
    }
    .map_err(Into::into)
}
