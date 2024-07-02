use std::io::{BufWriter, Write};

use clap::Subcommand;

use crate::{Outcome, RunArgs};

mod generate;
mod prepare;

#[derive(Debug, Clone, Subcommand)]
pub enum Args {
    Prepare(prepare::Args),
    Generate(generate::Args),
}

impl<T: Write> RunArgs<T> for Args {
    fn run(self, writer: &mut BufWriter<T>) -> Outcome {
        match self {
            Args::Prepare(args) => args.run(writer),
            Args::Generate(args) => args.run(writer),
        }
    }
}
