use crate::prelude::*;
use futures::{channel::mpsc::UnboundedReceiver, executor, stream::StreamExt};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    thread,
};

type BlockReceiver = UnboundedReceiver<Block>;

/// WSV reflects the current state of the system, can be considered as a snapshot. For example, WSV
/// holds information about an amount of assets that an account has at the moment but does not
/// contain any info history of transaction flow.
pub struct World {
    pub world_state_view: Arc<Mutex<WorldStateView>>,
    rx: Arc<Mutex<BlockReceiver>>,
}

impl World {
    pub fn new(rx: BlockReceiver) -> Self {
        World {
            world_state_view: Arc::new(Mutex::new(WorldStateView::new())),
            rx: Arc::new(Mutex::new(rx)),
        }
    }

    pub fn init(&self) {
        let rx = Arc::clone(&self.rx);
        let world_state_view = Arc::clone(&self.world_state_view);
        thread::spawn(move || {
            executor::block_on(run_the_world(rx, world_state_view));
        });
    }

    pub fn state_view(&self) -> Arc<Mutex<WorldStateView>> {
        //TODO: replace Mutex with RwLock to support parallel query execution.
        Arc::clone(&self.world_state_view)
    }
}

async fn run_the_world(
    rx: Arc<Mutex<BlockReceiver>>,
    world_state_view: Arc<Mutex<WorldStateView>>,
) {
    while let Some(block) = rx
        .lock()
        .expect("Failed to lock Block Receiver.")
        .next()
        .await
    {
        world_state_view
            .lock()
            .expect("Failed to lock World State View")
            .put(&block)
            .await;
    }
}

#[derive(Debug)]
pub struct WorldStateView {
    domains: HashMap<String, Domain>,
    transactions: HashMap<Hash, Transaction>,
}

impl WorldStateView {
    fn new() -> Self {
        WorldStateView {
            domains: HashMap::new(),
            transactions: HashMap::new(),
        }
    }

    /// Put `Block` of information with changes in form of **Iroha Special Instructions**
    /// into the world.
    pub async fn put(&mut self, block: &Block) {
        for transaction in &block.transactions {
            for instruction in &transaction.instructions {
                if let Err(e) = instruction.invoke(self) {
                    eprintln!("Failed to apply instruction to WSV: {}", e);
                }
            }
        }
    }

    pub fn add_domain(&mut self, domain: Domain) {
        self.domains.insert(domain.name.clone(), domain);
    }

    pub fn read_domain(&self, name: &str) -> Option<&Domain> {
        self.domains.get(name)
    }

    pub fn domain(&mut self, name: &str) -> Option<&mut Domain> {
        self.domains.get_mut(name)
    }

    pub fn read_account(&self, id: &Id) -> Option<&Account> {
        self.read_domain(&id.1)?.accounts.get(id)
    }

    pub fn account(&mut self, id: &Id) -> Option<&mut Account> {
        self.domain(&id.1)?.accounts.get_mut(id)
    }

    pub fn assets(&mut self, account_id: &Id, asset_id: &Id) -> Option<&mut Asset> {
        self.account(account_id)?.assets.get_mut(asset_id)
    }
}
