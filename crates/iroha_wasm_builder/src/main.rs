#![allow(missing_docs)]

use std::path::PathBuf;

use clap::{Args, Parser};
use color_eyre::eyre::{eyre, Context};
use iroha_wasm_builder::Builder;
use owo_colors::OwoColorize;

#[derive(Parser, Debug)]
#[command(name = "iroha_wasm_builder", version, author)]
enum Cli {
    /// Apply `cargo check` to the smartcontract
    Check {
        #[command(flatten)]
        common: CommonArgs,
        #[arg(long, default_value = "release")]
        profile: String,
    },
    /// Build the smartcontract
    Build {
        #[command(flatten)]
        common: CommonArgs,
        /// Build profile
        #[arg(long, default_value = "release")]
        profile: String,
        /// Where to store the output WASM. If the file exists, it will be overwritten.
        #[arg(long)]
        out_file: PathBuf,
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
            profile,
        } => {
            let builder = Builder::new(&path, &profile).show_output();
            builder.check()?;
        }
        Cli::Build {
            common: CommonArgs { path },
            out_file,
            profile,
        } => {
            let builder = Builder::new(&path, &profile).show_output();

            let output = {
                // not showing the spinner here, cargo does a progress bar for us
                match builder.build() {
                    Ok(output) => output,
                    err => err?,
                }
            };

            std::fs::copy(output.wasm_file_path(), &out_file).wrap_err_with(|| {
                eyre!(
                    "Failed to write the resulting file into {}",
                    out_file.display()
                )
            })?;

            println!(
                "✓ File is written into {}",
                out_file.display().green().bold()
            );
        }
    }

    Ok(())
}
