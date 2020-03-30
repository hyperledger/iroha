use crate::{block::Blockchain, prelude::*};

pub struct Sumeragi {
    blockchain: Blockchain,
}

impl Sumeragi {
    pub fn new(blockchain: Blockchain) -> Self {
        Sumeragi { blockchain }
    }

    pub async fn sign(&mut self, transactions: &[Transaction]) -> Result<(), ()> {
        self.vote(transactions)?;
        self.blockchain.accept(transactions.to_vec()).await;
        self.publish(transactions)?;
        Ok(())
    }

    fn vote(&self, _transactions: &[Transaction]) -> Result<(), ()> {
        Ok(())
    }

    fn publish(&self, _transactions: &[Transaction]) -> Result<(), ()> {
        Ok(())
    }
}
