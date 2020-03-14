use crate::{
    cache::{mst_cache::MSTCache, pending_tx_cache::PendingTxCache},
    consensus::sumeragi::Sumeragi,
    model::{block::Blockchain, commands::isi::Command, tx::Transaction},
};
use std::{
    io::prelude::*,
    net::TcpListener,
    thread::sleep,
    time::{Duration, Instant},
};

#[allow(dead_code)]
pub struct Torii {
    mst_cache: MSTCache,
    pending_tx_cache: PendingTxCache,
    consensus: Sumeragi,
    last_round_time: Instant,
    blockchain: Blockchain,
}

impl Torii {
    pub fn new() -> Self {
        Torii {
            mst_cache: MSTCache::default(),
            pending_tx_cache: PendingTxCache::default(),
            consensus: Sumeragi {},
            last_round_time: Instant::now(),
            blockchain: Blockchain::new(),
        }
    }

    pub fn start(&mut self) {
        let listener = TcpListener::bind("127.0.0.1:1337").expect("could not start server");
        for connection in listener.incoming() {
            match connection {
                Ok(mut stream) => {
                    let mut command_payload = Vec::new();
                    stream
                        .read_exact(&mut command_payload)
                        .expect("Command read failed.");
                    self.receive(command_payload.into());
                }
                Err(e) => {
                    println!("Connection failed {}.", e);
                }
            }
        }
    }

    fn receive(&mut self, command: Command) {
        self.pending_tx_cache.add_tx(
            Transaction::builder(vec![command], "account@domain".to_string())
                .build()
                .validate()
                .expect("Failed to validate transaction."),
        );
        sleep(Duration::new(2, 0));
        let transactions = self.pending_tx_cache.pop_all();
        self.consensus
            .vote(&transactions)
            .expect("Voting declined this block.");
        self.consensus
            .publish(&transactions)
            .expect("Publishing failed.");
        self.blockchain.push(transactions);
        self.last_round_time = Instant::now();
    }
}

impl Default for Torii {
    fn default() -> Self {
        Torii {
            mst_cache: MSTCache::default(),
            pending_tx_cache: PendingTxCache::default(),
            consensus: Sumeragi {},
            last_round_time: Instant::now(),
            blockchain: Blockchain::new(),
        }
    }
}
