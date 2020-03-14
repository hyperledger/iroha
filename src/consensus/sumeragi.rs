use crate::model::tx::Transaction;

pub struct Sumeragi {}

impl Sumeragi {
    pub fn vote(&self, _transactions: &[Transaction]) -> Result<(), ()> {
        Ok(())
    }

    pub fn publish(&self, _transactions: &[Transaction]) -> Result<(), ()> {
        Ok(())
    }
}
