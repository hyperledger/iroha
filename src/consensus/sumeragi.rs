use crate::model::{block::Blockchain, tx::Transaction};

pub struct Sumeragi {
    blockchain: Blockchain,
}

impl Sumeragi {
    pub fn new(blockchain: Blockchain) -> Self {
        Sumeragi { blockchain }
    }

    pub fn sign(&mut self, transactions: &[Transaction]) -> Result<(), ()> {
        self.vote(transactions)?;
        self.blockchain.accept(transactions.to_vec());
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
