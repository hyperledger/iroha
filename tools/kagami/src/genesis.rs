use std::io::{BufWriter, Write};

use clap::Subcommand;

use crate::{Outcome, RunArgs};

mod generate;
mod hash;
mod sign;

#[derive(Debug, Clone, Subcommand)]
pub enum Args {
    Sign(sign::Args),
    Generate(generate::Args),
    Hash(hash::Args),
}

impl<T: Write> RunArgs<T> for Args {
    fn run(self, writer: &mut BufWriter<T>) -> Outcome {
        match self {
            Args::Sign(args) => args.run(writer),
            Args::Generate(args) => args.run(writer),
            Args::Hash(args) => args.run(writer),
        }
    }
}
