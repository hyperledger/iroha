use crate::model::tx::Transaction;
use std::fmt::{Display, Formatter, Result};

#[derive(Default)]
pub struct PendingTxCache {
    pending_tx: Vec<Transaction>,
}

#[allow(dead_code)]
impl PendingTxCache {
    pub fn add_tx(&mut self, tx: Transaction) {
        self.pending_tx.push(tx);
    }

    pub fn pop_all(&mut self) -> Vec<Transaction> {
        self.pending_tx.drain(..).collect()
    }
}

impl Display for PendingTxCache {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "{:?}", self.pending_tx)
    }
}

#[test]
fn add_tx_to_cache() {
    let mut cache = PendingTxCache {
        pending_tx: Vec::new(),
    };
    cache.add_tx(Transaction::builder(Vec::new(), "account@domain".to_string()).build());
}
