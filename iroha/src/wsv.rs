use crate::prelude::*;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct WorldStateView {
    domains: HashMap<String, Domain>,
    transactions: HashMap<Hash, Transaction>,
    peer: Peer,
}

impl WorldStateView {
    pub fn new(peer: Peer) -> Self {
        WorldStateView {
            domains: HashMap::new(),
            transactions: HashMap::new(),
            peer,
        }
    }

    /// Put `Block` of information with changes in form of **Iroha Special Instructions**
    /// into the world.
    pub async fn put(&mut self, block: &Block) {
        for transaction in &block.transactions {
            if let Transaction::Valid {
                request: TransactionRequest { instructions, .. },
                ..
            } = transaction
            {
                for instruction in instructions {
                    if let Err(e) = instruction.invoke(self) {
                        eprintln!("Failed to apply instruction to WSV: {}", e);
                    }
                }
            } else {
                eprintln!("Transaction {:?} not in a Valid state.", transaction);
            }
        }
    }

    pub fn peer(&mut self) -> &mut Peer {
        &mut self.peer
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
        self.read_domain(&id.domain_name)?.accounts.get(id)
    }

    pub fn account(&mut self, id: &Id) -> Option<&mut Account> {
        self.domain(&id.domain_name)?.accounts.get_mut(id)
    }

    pub fn read_asset(&mut self, account_id: &Id, asset_id: &Id) -> Option<&mut Asset> {
        self.account(account_id)?.assets.get_mut(asset_id)
    }
}
