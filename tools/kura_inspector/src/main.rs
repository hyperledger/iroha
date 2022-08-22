//! Kura inspector binary. For usage run with `--help`.
#![allow(
    clippy::arithmetic,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc
)]
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use iroha_core::{
    kura::{BlockStoreTrait, StdFileBlockStore},
    prelude::VersionedCommittedBlock,
};
use iroha_version::scale::DecodeVersioned;

/// Kura inspector
#[derive(Parser)]
#[clap(author, version, about)]
struct Args {
    /// Height of the block from which start the inspection.
    /// Defaults to the latest block height
    #[clap(short, long, name = "BLOCK_HEIGHT")]
    from: Option<u64>,
    #[clap()]
    path_to_block_store: PathBuf,
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print contents of a certain length of the blocks
    Print {
        /// Number of the blocks to print.
        /// The excess will be truncated
        #[clap(short = 'n', long, default_value_t = 1)]
        length: u64,
    },
}

#[allow(clippy::use_debug, clippy::print_stderr, clippy::panic)]
fn main() {
    let args = Args::parse();

    let from_height = match args.from {
        Some(height) => {
            assert!(height != 0, "The genesis block has the height 1. Therefore, the \"from height\" you specify must not be 0.");
            // Kura starts counting blocks from 0 like an array while the outside world counts the first block as number 1.
            Some(height - 1)
        }
        None => None,
    };

    match args.command {
        Command::Print { length } => print_blockchain(
            &args.path_to_block_store,
            from_height.unwrap_or(u64::MAX),
            length,
        ),
    }
}

#[allow(
    clippy::print_stdout,
    clippy::use_debug,
    clippy::expect_used,
    clippy::expect_fun_call
)]
fn print_blockchain(block_store_path: &Path, from_height: u64, block_count: u64) {
    let block_store = StdFileBlockStore::new(block_store_path);

    let index_count = block_store
        .read_index_count()
        .expect("Failed to read index count from block store {block_store_path:?}.");
    assert!(
        index_count != 0,
        "Index count is zero. This could be because there are no blocks in the store: {:?}",
        block_store_path
    );

    let from_height = if from_height >= index_count {
        index_count - 1
    } else {
        from_height
    };

    let block_count = if from_height + block_count > index_count {
        index_count - from_height
    } else {
        block_count
    };

    let mut block_indices = vec![
        (0, 0);
        block_count
            .try_into()
            .expect("block_count didn't fit in 32-bits")
    ];
    block_store
        .read_block_indices(from_height, &mut block_indices)
        .expect("Failed to read block indices");
    let block_indices = block_indices;

    // Now for the actual printing
    println!("Index file says there are {} blocks.", index_count);
    println!(
        "Printing blocks {}-{}...",
        from_height + 1,
        from_height + block_count
    );

    for i in 0..block_count {
        let (index_start, index_len) =
            block_indices[usize::try_from(i).expect("i didn't fit in 32-bits")];
        let index_index = from_height + i;

        println!(
            "Block#{} starts at byte offset {} and is {} bytes long.",
            index_index + 1,
            index_start,
            index_len
        );
        let mut block_buf =
            vec![0_u8; usize::try_from(index_len).expect("index_len didn't fit in 32-bits")];
        block_store
            .read_block_data(index_start, &mut block_buf)
            .expect(&format!("Failed to read block № {} data.", index_index + 1));
        let block = VersionedCommittedBlock::decode_versioned(&block_buf)
            .expect(&format!("Failed to decode block № {}", index_index + 1));
        println!("Block#{} :", index_index + 1);
        println!("{:#?}", block);
    }
}
