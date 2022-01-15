//! Objects for the `print` subcommand.

use futures_util::StreamExt;
use iroha_core::{kura, prelude::VersionedCommittedBlock};

use crate::Output;

/// Configuration for the `print` subcommand.
#[derive(Clone, Copy)]
pub struct Config {
    /// Height of the block up to which exclude from the printing.
    /// `None` means excluding the all except the latest block.
    pub skip_to: Option<usize>,
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

        if let Some(height) = self.skip_to {
            let mut block_stream = block_stream.skip(height).take(self.length);
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

    use iroha_core::prelude::ValidBlock;

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

    #[tokio::test]
    /// Confirm that `print` command defaults to print the latest block.
    async fn test_print_default() {
        const BLOCK_COUNT: usize = 10;

        let dir = tempfile::tempdir().unwrap();
        let brock_store = block_store(&dir).await;
        let mut output = TestOutput::new();

        let mut tester = Vec::new();
        for height in 1..=BLOCK_COUNT {
            let mut block: VersionedCommittedBlock = ValidBlock::new_dummy().commit().into();
            block.as_mut_v1().header.height = height as u64;
            if BLOCK_COUNT == height {
                writeln!(tester, "{:#?}", block).unwrap()
            }
            brock_store.write(&block).await.unwrap();
        }
        let cfg = Config {
            skip_to: None,
            length: 1,
        };
        cfg.run(&brock_store, &mut output).await.unwrap();

        assert_eq!(tester, output.ok)
    }

    #[tokio::test]
    /// Confirm that `skip_to` and `length` options work properly.
    async fn test_print_range() {
        const BLOCK_COUNT: usize = 10;
        const SKIP_TO: usize = 2;
        const LENGTH: usize = 5;

        let dir = tempfile::tempdir().unwrap();
        let brock_store = block_store(&dir).await;
        let mut output = TestOutput::new();

        let mut tester = Vec::new();
        for height in 1..=BLOCK_COUNT {
            let mut block: VersionedCommittedBlock = ValidBlock::new_dummy().commit().into();
            block.as_mut_v1().header.height = height as u64;
            if (SKIP_TO + 1..=SKIP_TO + LENGTH).contains(&height) {
                writeln!(tester, "{:#?}", block).unwrap()
            }
            brock_store.write(&block).await.unwrap();
        }
        let cfg = Config {
            skip_to: Some(SKIP_TO),
            length: LENGTH,
        };
        cfg.run(&brock_store, &mut output).await.unwrap();

        assert_eq!(tester, output.ok)
    }
}
