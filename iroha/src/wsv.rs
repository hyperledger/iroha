use crate::prelude::*;
use std::collections::HashMap;

/// WSV reflects the current state of the system, can be considered as a snapshot. For example, WSV
/// holds information about an amount of assets that an account has at the moment but does not
/// contain any info history of transaction flow.
pub struct WorldStateView {
    pub world: World,
}

impl WorldStateView {
    pub fn new() -> Self {
        WorldStateView {
            world: World::new(),
        }
    }

    pub async fn init(blocks: &[&Block]) -> Self {
        let mut world_state_view = WorldStateView::new();
        for block in blocks {
            world_state_view.put(block).await;
        }
        world_state_view
    }

    /// Put `Block` of information with changes in form of **Iroha Special Instructions**
    /// into the world.
    pub async fn put(&mut self, block: &Block) {
        for transaction in &block.transactions {
            for instruction in &transaction.instructions {
                instruction.apply(self);
            }
        }
    }
}

impl Default for WorldStateView {
    fn default() -> Self {
        Self::new()
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
