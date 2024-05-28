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
    },
    /// Build the smartcontract
    Build {
        #[command(flatten)]
        common: CommonArgs,
        /// Optimize WASM output.
        #[arg(long)]
        optimize: bool,
        /// Where to store the output WASM. If the file exists, it will be overwritten.
        #[arg(long)]
        outfile: PathBuf,
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
            let builder = Builder::new(&path).show_output();
            builder.check()?;
        }
        Cli::Build {
            common: CommonArgs { path },
            optimize,
            outfile,
        } => {
            let builder = Builder::new(&path).show_output();

            let output = {
                // not showing the spinner here, cargo does a progress bar for us

                match builder.build() {
                    Ok(output) => output,
                    err => err?,
                }
            };

            let output = if optimize {
                let mut sp = spinoff::Spinner::new_with_stream(
                    spinoff::spinners::Binary,
                    "Optimizing the output",
                    None,
                    spinoff::Streams::Stderr,
                );

                match output.optimize() {
                    Ok(optimized) => {
                        sp.success("Output is optimized");
                        optimized
                    }
                    err => {
                        sp.fail("Optimization failed");
                        err?
                    }
                }
            } else {
                output
            };

            std::fs::copy(output.wasm_file_path(), &outfile).wrap_err_with(|| {
                eyre!(
                    "Failed to write the resulting file into {}",
                    outfile.display()
                )
            })?;

            println!(
                "✓ File is written into {}",
                outfile.display().green().bold()
            );
        }
    }

    Ok(())
}
