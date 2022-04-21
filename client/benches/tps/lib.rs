use std::{fmt, fs::File, io::BufReader, path::Path, sync::mpsc, thread, time};

use eyre::{Result, WrapErr};
use iroha_client::client::Client;
use iroha_data_model::prelude::*;
use serde::Deserialize;
use test_network::*;

pub type Tps = f64;

#[derive(Debug, Clone, Copy, Deserialize)]
pub struct Config {
    pub peers: u32,
    /// Interval in microseconds between transactions to reduce load
    pub interval_us_per_tx: u64,
    pub max_txs_per_block: u32,
    pub blocks: u32,
    pub sample_size: u32,
}

impl fmt::Display for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}peers-{}interval_us-{}max_txs-{}blocks-{}samples",
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

    #[allow(clippy::expect_used, clippy::unwrap_in_result)]
    pub fn measure(self) -> Result<Tps> {
        // READY
        let (_rt, network, _genesis_client) =
            <Network>::start_test_with_runtime(self.peers, self.max_txs_per_block);
        let clients = network.clients();
        wait_for_genesis_committed(&clients, 0);

        let unit_names = (UnitName::MIN..).take(self.peers as usize);
        let units = clients
            .into_iter()
            .zip(unit_names.clone().zip(unit_names.cycle().skip(1)))
            .map(|(client, pair)| {
                let unit = MeasurerUnit {
                    config: self,
                    client,
                    name: pair.0,
                    next_name: pair.1,
                };
                unit.ready()
            })
            .collect::<Result<Vec<_>>>()?;

        let mut handles = Vec::new();
        for unit in &units {
            let handle = unit.spawn_event_counter();
            handles.push(handle)
        }
        // START
        let timer = time::Instant::now();
        for unit in &units {
            unit.spawn_transaction_submitter();
        }
        for handle in handles {
            handle.join().expect("Event counter panicked")?;
        }
        // END
        let elapsed_secs = timer.elapsed().as_secs_f64();
        thread::sleep(core::time::Duration::from_secs(2));
        let blocks_out_of_measure = 1 + 2 * self.peers;
        let mut blocks = network
            .genesis
            .iroha
            .as_ref()
            .expect("Must be some")
            .wsv
            .blocks()
            .skip(blocks_out_of_measure as usize);
        let (txs_accepted, txs_rejected) = (0..self.blocks)
            .map(|_| {
                let block = blocks
                    .next()
                    .expect("The block is not yet in WSV. Need more sleep?");
                let block = block.as_v1();
                (block.transactions.len(), block.rejected_transactions.len())
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
    pub next_name: UnitName,
}

type UnitName = u32;

impl MeasurerUnit {
    /// Submit initial transactions for measurement
    #[allow(clippy::expect_used, clippy::unwrap_in_result)]
    fn ready(mut self) -> Result<Self> {
        let (public_key, _) = iroha_core::prelude::KeyPair::generate()
            .expect("Failed to generate KeyPair.")
            .into();

        let register_me = RegisterBox::new(Account::new(account_id(self.name), [public_key]));
        let mint_a_rose = MintBox::new(1_u32, asset_id(self.name));

        let _ = self.client.submit_blocking(register_me)?;
        let _ = self.client.submit_blocking(mint_a_rose)?;

        Ok(self)
    }

    /// Spawn who checks if all the expected blocks are committed
    #[allow(clippy::expect_used)]
    fn spawn_event_counter(&self) -> thread::JoinHandle<Result<()>> {
        let mut listener = self.client.clone();
        let (init_sender, init_receiver) = mpsc::channel();
        let event_filter = PipelineEventFilter::new()
            .entity_kind(PipelineEntityKind::Block)
            .status_kind(PipelineStatusKind::Committed)
            .into();
        let blocks_expected = self.config.blocks as usize;
        let handle = thread::spawn(move || -> Result<()> {
            let mut event_iterator = listener.listen_for_events(event_filter)?;
            init_sender.send(())?;
            for _ in 0..blocks_expected {
                let _event = event_iterator.next().expect("Event stream closed")?;
            }
            Ok(())
        });
        init_receiver
            .recv()
            .expect("Failed to initialize an event counter");

        handle
    }

    /// Spawn who periodically submits transactions
    fn spawn_transaction_submitter(&self) {
        let mut submitter = self.client.clone();
        let interval_us_per_tx = self.config.interval_us_per_tx;
        let instructions = self.instructions();
        thread::spawn(move || -> Result<()> {
            for instruction in instructions {
                submitter.submit(instruction)?;
                thread::sleep(core::time::Duration::from_micros(interval_us_per_tx));
            }
            Ok(())
        });
    }

    #[allow(clippy::expect_used)]
    fn instructions(&self) -> impl Iterator<Item = Instruction> {
        [self.mint_or_burn(), self.relay_a_rose()]
            .into_iter()
            .cycle()
    }

    fn mint_or_burn(&self) -> Instruction {
        let is_running_out: Expression = Less::new(
            Expression::Query(FindAssetQuantityById::new(asset_id(self.name)).into()),
            Value::U32(100),
        )
        .into();
        let supply_roses = MintBox::new(Value::U32(100), asset_id(self.name));
        let burn_a_rose = BurnBox::new(Value::U32(1), asset_id(self.name));

        IfInstruction::with_otherwise(is_running_out, supply_roses, burn_a_rose).into()
    }

    fn relay_a_rose(&self) -> Instruction {
        TransferBox::new(asset_id(self.name), Value::U32(1), asset_id(self.next_name)).into()
    }
}

#[allow(clippy::expect_used)]
fn asset_id(account_name: UnitName) -> AssetId {
    AssetId::new(
        "rose#wonderland".parse().expect("Valid"),
        account_id(account_name),
    )
}

#[allow(clippy::expect_used)]
fn account_id(name: UnitName) -> AccountId {
    format!("{}@wonderland", name).parse().expect("Valid")
}
