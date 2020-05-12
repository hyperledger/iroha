use crate::prelude::*;

#[derive(Debug, Clone)]
pub struct WorldStateView {
    peer: Peer,
}

impl WorldStateView {
    pub fn new(peer: Peer) -> Self {
        WorldStateView { peer }
    }

    /// Put `ValidBlock` of information with changes in form of **Iroha Special Instructions**
    /// into the world.
    pub async fn put(&mut self, block: &ValidBlock) {
        for transaction in &block.transactions {
            if let Err(e) = &transaction.proceed(self) {
                eprintln!("Failed to procced transaction on WSV: {}", e);
            }
        }
    }

    pub fn peer(&mut self) -> &mut Peer {
        &mut self.peer
    }

    pub fn add_domain(&mut self, domain: Domain) {
        self.peer.domains.insert(domain.name.clone(), domain);
    }

    pub fn read_domain(&self, name: &str) -> Option<&Domain> {
        self.peer.domains.get(name)
    }

    pub fn domain(&mut self, name: &str) -> Option<&mut Domain> {
        self.peer.domains.get_mut(name)
    }

    pub fn read_account(&self, id: &<Account as Identifiable>::Id) -> Option<&Account> {
        self.read_domain(&id.container)?.accounts.get(id)
    }

    pub fn account(&mut self, id: &<Account as Identifiable>::Id) -> Option<&mut Account> {
        self.domain(&id.container)?.accounts.get_mut(id)
    }

    pub fn read_asset(
        &mut self,
        account_id: &<Account as Identifiable>::Id,
        asset_id: &<Asset as Identifiable>::Id,
    ) -> Option<&mut Asset> {
        self.account(account_id)?.assets.get_mut(asset_id)
    }

    pub fn asset(&mut self, id: &<Asset as Identifiable>::Id) -> Option<&mut Asset> {
        self.account(&id.account_id())?.assets.get_mut(id)
    }
}
