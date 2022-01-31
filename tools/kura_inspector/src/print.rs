//! Objects for the `print` subcommand.

use futures_util::StreamExt;
use iroha_core::{kura, prelude::VersionedCommittedBlock};

use crate::Output;

/// Configuration for the `print` subcommand.
#[derive(Clone, Copy)]
pub struct Config {
    /// Height of the block from which start the printing.
    /// `None` means printing only the latest block.
    pub from: Option<usize>,
    /// Number of the blocks to print.
    /// The excess will be truncated.
    pub length: usize,
}

impl Config {
    /// Read `block_store` and print the results to `output`.
    ///
    /// # Errors
    /// Fails if
    /// 1. Fails to read `block_store`.
    /// 2. Fails to print to `output`.
    /// 3. Tries to print the latest block and there is none.
    pub async fn run<T, E>(
        &self,
        block_store: &kura::BlockStore<kura::DefaultIO>,
        output: &mut Output<T, E>,
    ) -> Result<(), Error>
    where
        T: std::io::Write + Send,
        E: std::io::Write + Send,
    {
        let block_stream = block_store
            .read_all()
            .await
            .map_err(Box::new)
            .map_err(Error::ReadBlockStore)?;
        tokio::pin!(block_stream);

        if let Some(height) = self.from {
            let mut block_stream = block_stream
                .skip(height.saturating_sub(1))
                .take(self.length);
            while let Some(block_result) = block_stream.next().await {
                output.print(block_result).map_err(Error::Output)?
            }
        } else {
            let last = match block_stream.next().await {
                Some(block_result) => {
                    block_stream
                        .fold(block_result, |_acc, x| async move { x })
                        .await
                }
                None => return Err(Error::NoBlock),
            };
            output.print(last).map_err(Error::Output)?
        }
        Ok(())
    }
}

impl<T, E> Output<T, E>
where
    T: std::io::Write + Send,
    E: std::io::Write + Send,
{
    #[allow(clippy::use_debug)]
    fn print(
        &mut self,
        block_result: Result<VersionedCommittedBlock, kura::Error>,
    ) -> Result<(), std::io::Error> {
        match block_result {
            Ok(block) => writeln!(self.ok, "{:#?}", block),
            Err(error) => writeln!(self.err, "{:#?}", error),
        }
    }
}

#[derive(Debug)]
#[allow(missing_docs)]
pub enum Error {
    ReadBlockStore(Box<kura::Error>),
    Output(std::io::Error),
    NoBlock,
}

#[cfg(test)]
#[allow(clippy::restriction)]
mod tests {
    use std::io::Write;

    use super::*;

    type TestOutput = Output<Vec<u8>, Vec<u8>>;
    const BLOCKS_PER_FILE: u64 = 3;

    impl TestOutput {
        fn new() -> Self {
            Self {
                ok: Vec::new(),
                err: Vec::new(),
            }
        }
    }

    async fn block_store(dir: &tempfile::TempDir) -> kura::BlockStore<kura::DefaultIO> {
        kura::BlockStore::new(
            dir.path(),
            std::num::NonZeroU64::new(BLOCKS_PER_FILE).unwrap(),
            kura::DefaultIO,
        )
        .await
        .unwrap()
    }

    fn block() -> VersionedCommittedBlock {
        use iroha_core::block::{BlockHeader, EmptyChainHash, ValidBlock};

        ValidBlock {
            header: BlockHeader {
                timestamp: 0,
                height: 1,
                previous_block_hash: EmptyChainHash::default().into(),
                transactions_hash: EmptyChainHash::default().into(),
                rejected_transactions_hash: EmptyChainHash::default().into(),
                view_change_proofs: iroha_core::sumeragi::view_change::ProofChain::empty(),
                invalidated_blocks_hashes: Vec::new(),
                genesis_topology: None,
            },
            rejected_transactions: vec![],
            transactions: vec![],
            signatures: std::collections::BTreeSet::default(),
        }
        .sign(iroha_core::prelude::KeyPair::generate().unwrap())
        .unwrap()
        .commit()
        .into()
    }

    #[tokio::test]
    /// Confirm that `print` command defaults to print the latest block.
    async fn test_print_default() {
        const BLOCK_COUNT: usize = 10;

        let dir = tempfile::tempdir().unwrap();
        let block_store = block_store(&dir).await;
        let mut output = TestOutput::new();

        let mut tester = Vec::new();
        for height in 1..=BLOCK_COUNT {
            let mut block = block();
            block.as_mut_v1().header.height = height as u64;
            if BLOCK_COUNT == height {
                writeln!(tester, "{:#?}", block).unwrap()
            }
            block_store.write(&block).await.unwrap();
        }
        let cfg = Config {
            from: None,
            length: 1,
        };
        cfg.run(&block_store, &mut output).await.unwrap();

        assert_eq!(tester, output.ok)
    }

    #[tokio::test]
    /// Confirm that `from` and `length` options work properly.
    async fn test_print_range() {
        const BLOCK_COUNT: usize = 10;
        const FROM: usize = 3;
        const LENGTH: usize = 5;

        let dir = tempfile::tempdir().unwrap();
        let block_store = block_store(&dir).await;
        let mut output = TestOutput::new();

        let mut tester = Vec::new();
        for height in 1..=BLOCK_COUNT {
            let mut block = block();
            block.as_mut_v1().header.height = height as u64;
            if (FROM..FROM + LENGTH).contains(&height) {
                writeln!(tester, "{:#?}", block).unwrap()
            }
            block_store.write(&block).await.unwrap();
        }
        let cfg = Config {
            from: Some(FROM),
            length: LENGTH,
        };
        cfg.run(&block_store, &mut output).await.unwrap();

        assert_eq!(tester, output.ok)
    }
}
