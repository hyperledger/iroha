use crate::prelude::*;
use futures::{channel::mpsc::UnboundedReceiver, stream::StreamExt};
use std::collections::HashMap;

type BlockReceiver = UnboundedReceiver<Block>;

/// WSV reflects the current state of the system, can be considered as a snapshot. For example, WSV
/// holds information about an amount of assets that an account has at the moment but does not
/// contain any info history of transaction flow.
pub struct WorldStateView {
    pub world: World,
    rx: BlockReceiver,
}

impl WorldStateView {
    pub fn new(rx: BlockReceiver) -> Self {
        WorldStateView {
            world: World::new(),
            rx,
        }
    }

    pub async fn init(mut self, blocks: &[&Block]) {
        for block in blocks {
            self.put(block).await;
        }
    }

    pub async fn start(&mut self) {
        while let Some(block) = self.rx.next().await {
            self.put(&block).await;
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
}

#[derive(Debug)]
pub struct World {
    domains: HashMap<String, Domain>,
    transactions: HashMap<Hash, Transaction>,
}

impl World {
    fn new() -> Self {
        World {
            domains: HashMap::new(),
            transactions: HashMap::new(),
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
