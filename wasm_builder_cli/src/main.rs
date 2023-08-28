use std::{
    io::{stdout, BufWriter, Write},
    path::PathBuf,
};

use clap::{Args, Parser};
use color_eyre::eyre::Context;
use iroha_wasm_builder::Builder;

#[derive(Parser, Debug)]
#[command(name = "iroha_wasm_builder_cli", version, author)]
enum Cli {
    /// Apply `cargo check` to the smartcontract
    Check {
        #[command(flatten)]
        common: CommonArgs,
    },
    /// Build the smartcontract
    Build {
        #[command(flatten)]
        common: CommonArgs,
        /// Enable smartcontract formatting using `cargo fmt`.
        // TODO: why it is a part of `build` in wasm_builder?
        #[arg(long)]
        format: bool,
        /// Optimize WASM output.
        #[arg(long)]
        optimize: bool,
    },
}

#[derive(Args, Debug)]
struct CommonArgs {
    /// Path to the smartcontract
    path: PathBuf,
}

fn main() -> color_eyre::Result<()> {
    match Cli::parse() {
        Cli::Check {
            common: CommonArgs { path },
        } => {
            let builder = Builder::new(&path);
            builder.check()?;
        }
        Cli::Build {
            common: CommonArgs { path },
            format,
            optimize,
        } => {
            let builder = Builder::new(&path);
            let builder = if format { builder.format() } else { builder };

            let output = builder.build().wrap_err("Failed to build")?;
            let output = if optimize {
                output.optimize().wrap_err("Failed to apply --optimize")?
            } else {
                output
            };

            let bytes = output
                .into_bytes()
                .wrap_err("Failed to fetch the bytes of the output smartcontract")?;

            let mut writer = BufWriter::new(stdout());
            writer
                .write_all(&bytes)
                .wrap_err("Failed to output the bytes")?;
        }
    }

    Ok(())
}
