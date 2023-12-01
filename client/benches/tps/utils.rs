use std::{
    fmt,
    fs::File,
    io::BufReader,
    num::NonZeroU32,
    path::Path,
    str::FromStr as _,
    sync::mpsc,
    thread::{self, JoinHandle},
    time,
};

use eyre::{Result, WrapErr};
use iroha_client::{
    client::Client,
    data_model::{
        parameter::{default::MAX_TRANSACTIONS_IN_BLOCK, ParametersBuilder},
        prelude::*,
    },
};
use serde::Deserialize;
use serde_json::json;
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
        wait_for_genesis_committed(&clients, 0);

        client.submit_blocking(
            ParametersBuilder::new()
                .add_parameter(MAX_TRANSACTIONS_IN_BLOCK, self.max_txs_per_block)?
                .into_set_parameters(),
        )?;

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
        let blocks_wsv = network
            .genesis
            .iroha
            .as_ref()
            .expect("Must be some")
            .sumeragi
            .wsv_clone();
        let mut blocks = blocks_wsv.all_blocks().skip(blocks_out_of_measure as usize);
        let (txs_accepted, txs_rejected) = (0..self.blocks)
            .map(|_| {
                let block = blocks
                    .next()
                    .expect("The block is not yet in WSV. Need more sleep?");
                (
                    block
                        .payload()
                        .transactions
                        .iter()
                        .filter(|tx| tx.error.is_none())
                        .count(),
                    block
                        .payload()
                        .transactions
                        .iter()
                        .filter(|tx| tx.error.is_some())
                        .count(),
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
    pub next_name: UnitName,
}

type UnitName = u32;

impl MeasurerUnit {
    /// Number of blocks that will be committed by [`Self::ready()`] call
    const PREPARATION_BLOCKS_NUMBER: u32 = 3;

    /// Submit initial transactions for measurement
    fn ready(self) -> Result<Self> {
        let keypair =
            iroha_client::crypto::KeyPair::generate().expect("Failed to generate KeyPair.");

        let account_id = account_id(self.name);
        let alice_id = AccountId::from_str("alice@wonderland")?;
        let asset_id = asset_id(self.name);

        let register_me = RegisterExpr::new(Account::new(
            account_id.clone(),
            [keypair.public_key().clone()],
        ));
        self.client.submit_blocking(register_me)?;

        let can_burn_my_asset = PermissionToken::new(
            "CanBurnUserAsset".parse().unwrap(),
            &json!({ "asset_id": asset_id }),
        );
        let allow_alice_to_burn_my_asset = GrantExpr::new(can_burn_my_asset, alice_id.clone());
        let can_transfer_my_asset = PermissionToken::new(
            "CanTransferUserAsset".parse().unwrap(),
            &json!({ "asset_id": asset_id }),
        );
        let allow_alice_to_transfer_my_asset = GrantExpr::new(can_transfer_my_asset, alice_id);
        let grant_tx = TransactionBuilder::new(account_id)
            .with_instructions([
                allow_alice_to_burn_my_asset,
                allow_alice_to_transfer_my_asset,
            ])
            .sign(keypair)?;
        self.client.submit_transaction_blocking(&grant_tx)?;

        let mint_a_rose = MintExpr::new(1_u32, asset_id);
        self.client.submit_blocking(mint_a_rose)?;

        Ok(self)
    }

    /// Spawn who checks if all the expected blocks are committed
    fn spawn_event_counter(&self) -> thread::JoinHandle<Result<()>> {
        let listener = self.client.clone();
        let (init_sender, init_receiver) = mpsc::channel();
        let event_filter = PipelineEventFilter::new()
            .entity_kind(PipelineEntityKind::Block)
            .status_kind(PipelineStatusKind::Committed)
            .into();
        let blocks_expected = self.config.blocks as usize;
        let name = self.name;
        let handle = thread::spawn(move || -> Result<()> {
            let mut event_iterator = listener.listen_for_events(event_filter)?;
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
    fn spawn_transaction_submitter(&self, shutdown_signal: mpsc::Receiver<()>) -> JoinHandle<()> {
        let submitter = self.client.clone();
        let interval_us_per_tx = self.config.interval_us_per_tx;
        let instructions = self.instructions();
        let alice_id = AccountId::from_str("alice@wonderland").expect("Failed to parse account id");

        let mut nonce = NonZeroU32::new(1).expect("Valid");

        thread::spawn(move || {
            for instruction in instructions {
                match shutdown_signal.try_recv() {
                    Err(mpsc::TryRecvError::Empty) => {
                        let mut transaction = TransactionBuilder::new(alice_id.clone())
                            .with_instructions([instruction]);
                        transaction.set_nonce(nonce); // Use nonce to avoid transaction duplication within the same thread

                        let transaction = submitter
                            .sign_transaction(transaction)
                            .expect("Failed to sign transaction");
                        if let Err(error) = submitter.submit_transaction(&transaction) {
                            iroha_logger::error!(?error, "Failed to submit transaction");
                        }

                        nonce = nonce.checked_add(1).or(NonZeroU32::new(1)).expect("Valid");
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

    fn instructions(&self) -> impl Iterator<Item = InstructionExpr> {
        [self.mint_or_burn(), self.relay_a_rose()]
            .into_iter()
            .cycle()
    }

    fn mint_or_burn(&self) -> InstructionExpr {
        let is_running_out = Less::new(
            EvaluatesTo::new_unchecked(Expression::Query(
                FindAssetQuantityById::new(asset_id(self.name)).into(),
            )),
            100_u32,
        );
        let supply_roses = MintExpr::new(100_u32.to_value(), asset_id(self.name));
        let burn_a_rose = BurnExpr::new(1_u32.to_value(), asset_id(self.name));

        ConditionalExpr::with_otherwise(is_running_out, supply_roses, burn_a_rose).into()
    }

    fn relay_a_rose(&self) -> InstructionExpr {
        // Save at least one rose
        // because if asset value hits 0 it's automatically deleted from account
        // and query `FindAssetQuantityById` return error
        let enough_to_transfer = Greater::new(
            EvaluatesTo::new_unchecked(Expression::Query(
                FindAssetQuantityById::new(asset_id(self.name)).into(),
            )),
            1_u32,
        );
        let transfer_rose = TransferExpr::new(
            asset_id(self.name),
            1_u32.to_value(),
            account_id(self.next_name),
        );

        ConditionalExpr::new(enough_to_transfer, transfer_rose).into()
    }
}

fn asset_id(account_name: UnitName) -> AssetId {
    AssetId::new(
        "rose#wonderland".parse().expect("Valid"),
        account_id(account_name),
    )
}

fn account_id(name: UnitName) -> AccountId {
    format!("{name}@wonderland").parse().expect("Valid")
}
