use std::fmt;
use crate::model::model;

pub struct PendingTxCache {
    pending_tx: Vec<model::Transaction>
}

impl PendingTxCache {
    // constructor
    pub fn new() -> PendingTxCache {
        PendingTxCache {
            pending_tx: Vec::new()
        }
    }

	pub fn add_tx(&mut self, tx: model::Transaction) {
		self.pending_tx.push(tx);
	}
}

impl fmt::Display for PendingTxCache {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.pending_tx)//TODO:
    }
}
