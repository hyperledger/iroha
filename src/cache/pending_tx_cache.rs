use crate::model::model;
use std::fmt;

#[derive(Default)]
pub struct PendingTxCache {
    pending_tx: Vec<model::Transaction>,
}

impl PendingTxCache {
    pub fn add_tx(&mut self, tx: model::Transaction) {
        self.pending_tx.push(tx);
    }
}

impl fmt::Display for PendingTxCache {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.pending_tx) //TODO:
    }
}
