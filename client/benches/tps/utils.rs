use std::{fmt, fs::File, io::BufReader, path::Path, sync::mpsc, thread, time};

use eyre::{Result, WrapErr};
use iroha_client::{
    client::Client,
    crypto::KeyPair,
    data_model::{
        parameter::{default::MAX_TRANSACTIONS_IN_BLOCK, ParametersBuilder},
        prelude::*,
    },
};
use iroha_data_model::events::pipeline::{BlockEventFilter, BlockStatus};
use nonzero_ext::nonzero;
use serde::Deserialize;
use test_network::*;
use test_samples::ALICE_ID;

pub type Tps = f64;

#[derive(Debug, Clone, Copy, Deserialize)]
pub struct Config {
    pub peers: u32,
    /// Interval in microseconds between transactions to reduce load
    pub interval_us_per_tx: u64,
    pub max_txs_per_block: u32,
    pub blocks: u32,
    pub sample_size: u32,
    pub genesis_max_retries: u32,
}

impl fmt::Display for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}peers-{}interval_µs-{}max_txs-{}blocks-{}samples",
            self.peers,
            self.interval_us_per_tx,
            self.max_txs_per_block,
            self.blocks,
            self.sample_size,
        )
    }
}

impl Config {
    pub fn from_path<P: AsRef<Path> + fmt::Debug>(path: P) -> Result<Self> {
        let file = File::open(path).wrap_err("Failed to open the config file")?;
        let reader = BufReader::new(file);
        serde_json::from_reader(reader).wrap_err("Failed to deserialize json from reader")
    }

    pub fn measure(self) -> Result<Tps> {
        // READY
        let (_rt, network, client) = Network::start_test_with_runtime(self.peers, None);
        let clients = network.clients();
        wait_for_genesis_committed_with_max_retries(&clients, 0, self.genesis_max_retries);

        client.submit_all_blocking(
            ParametersBuilder::new()
                .add_parameter(MAX_TRANSACTIONS_IN_BLOCK, self.max_txs_per_block)?
                .into_set_parameters(),
        )?;

        let unit_names = (UnitName::MIN..).take(self.peers as usize);
        let units = clients
            .into_iter()
            .zip(unit_names)
            .map(|(client, name)| {
                let unit = MeasurerUnit {
                    config: self,
                    client,
                    name,
                    signatory: KeyPair::random().into_parts().0,
                };
                unit.ready()
            })
            .collect::<Result<Vec<_>>>()?;

        let event_counter_handles = units
            .iter()
            .map(MeasurerUnit::spawn_event_counter)
            .collect::<Vec<_>>();

        // START
        let timer = time::Instant::now();
        let transaction_submitter_handles = units
            .iter()
            .map(|unit| {
                let (shutdown_sender, shutdown_reciever) = mpsc::channel();
                let handle = unit.spawn_transaction_submitter(shutdown_reciever);
                (handle, shutdown_sender)
            })
            .collect::<Vec<_>>();

        // Wait for slowest peer to commit required number of blocks
        for handle in event_counter_handles {
            handle.join().expect("Event counter panicked")?;
        }

        // END
        let elapsed_secs = timer.elapsed().as_secs_f64();

        // Stop transaction submitters
        for (handle, shutdown_sender) in transaction_submitter_handles {
            shutdown_sender
                .send(())
                .expect("Failed to send shutdown signal");
            handle.join().expect("Transaction submitter panicked");
        }

        let blocks_out_of_measure = 2 + MeasurerUnit::PREPARATION_BLOCKS_NUMBER * self.peers;
        let state_view = network
            .genesis
            .iroha
            .as_ref()
            .expect("Must be some")
            .state
            .view();
        let mut blocks = state_view.all_blocks().skip(blocks_out_of_measure as usize);
        let (txs_accepted, txs_rejected) = (0..self.blocks)
            .map(|_| {
                let block = blocks
                    .next()
                    .expect("The block is not yet in state. Need more sleep?");
                (
                    block.transactions().filter(|tx| tx.error.is_none()).count(),
                    block.transactions().filter(|tx| tx.error.is_some()).count(),
                )
            })
            .fold((0, 0), |acc, pair| (acc.0 + pair.0, acc.1 + pair.1));
        #[allow(clippy::float_arithmetic, clippy::cast_precision_loss)]
        let tps = txs_accepted as f64 / elapsed_secs;
        iroha_logger::info!(%tps, %txs_accepted, %elapsed_secs, %txs_rejected);
        Ok(tps)
    }
}

struct MeasurerUnit {
    pub config: Config,
    pub client: Client,
    pub name: UnitName,
    pub signatory: PublicKey,
}

type UnitName = u32;

impl MeasurerUnit {
    /// Number of blocks that will be committed by [`Self::ready()`] call
    const PREPARATION_BLOCKS_NUMBER: u32 = 2;

    /// Submit initial transactions for measurement
    fn ready(self) -> Result<Self> {
        let register_me = Register::account(Account::new(self.account_id()));
        self.client.submit_blocking(register_me)?;

        let mint_a_rose = Mint::asset_numeric(1_u32, self.asset_id());
        self.client.submit_blocking(mint_a_rose)?;

        Ok(self)
    }

    /// Spawn who checks if all the expected blocks are committed
    fn spawn_event_counter(&self) -> thread::JoinHandle<Result<()>> {
        let listener = self.client.clone();
        let (init_sender, init_receiver) = mpsc::channel();
        let event_filter = BlockEventFilter::default().for_status(BlockStatus::Applied);
        let blocks_expected = self.config.blocks as usize;
        let name = self.name;
        let handle = thread::spawn(move || -> Result<()> {
            let mut event_iterator = listener.listen_for_events([event_filter])?;
            init_sender.send(())?;
            for i in 1..=blocks_expected {
                let _event = event_iterator.next().expect("Event stream closed")?;
                iroha_logger::info!(name, block = i, "Received block committed event");
            }
            Ok(())
        });
        init_receiver
            .recv()
            .expect("Failed to initialize an event counter");

        handle
    }

    /// Spawn who periodically submits transactions
    fn spawn_transaction_submitter(
        &self,
        shutdown_signal: mpsc::Receiver<()>,
    ) -> thread::JoinHandle<()> {
        let chain_id = ChainId::from("0");

        let submitter = self.client.clone();
        let interval_us_per_tx = self.config.interval_us_per_tx;
        let instructions = self.instructions();
        let alice_id = ALICE_ID.clone();

        let mut nonce = nonzero!(1_u32);

        thread::spawn(move || {
            for instruction in instructions {
                match shutdown_signal.try_recv() {
                    Err(mpsc::TryRecvError::Empty) => {
                        let mut transaction =
                            TransactionBuilder::new(chain_id.clone(), alice_id.clone())
                                .with_instructions([instruction]);
                        transaction.set_nonce(nonce); // Use nonce to avoid transaction duplication within the same thread

                        let transaction = submitter.sign_transaction(transaction);
                        if let Err(error) = submitter.submit_transaction(&transaction) {
                            iroha_logger::error!(?error, "Failed to submit transaction");
                        }

                        nonce = nonce.checked_add(1).unwrap_or(nonzero!(1_u32));
                        thread::sleep(time::Duration::from_micros(interval_us_per_tx));
                    }
                    Err(mpsc::TryRecvError::Disconnected) => {
                        panic!("Unexpected disconnection of shutdown sender");
                    }
                    Ok(()) => {
                        iroha_logger::info!("Shutdown transaction submitter");
                        return;
                    }
                }
            }
        })
    }

    fn instructions(&self) -> impl Iterator<Item = InstructionBox> {
        std::iter::once(self.mint()).cycle()
    }

    fn mint(&self) -> InstructionBox {
        Mint::asset_numeric(1_u32, self.asset_id()).into()
    }

    fn account_id(&self) -> AccountId {
        AccountId::new("wonderland".parse().expect("Valid"), self.signatory.clone())
    }

    fn asset_id(&self) -> AssetId {
        AssetId::new("rose#wonderland".parse().expect("Valid"), self.account_id())
    }
}
