use crate::model;
use std::fmt;

#[derive(Default)]
pub struct PendingTxCache {
    pending_tx: Vec<model::Transaction>,
}

#[allow(dead_code)]
impl PendingTxCache {
    pub fn add_tx(&mut self, tx: model::Transaction) {
        self.pending_tx.push(tx);
    }
}

impl fmt::Display for PendingTxCache {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.pending_tx)
    }
}

#[test]
fn add_tx_to_cache() {
    let mut cache = PendingTxCache {
        pending_tx: Vec::new(),
    };
    cache.add_tx(model::Transaction {
        account_id: "account@domain".to_string(),
        commands: Vec::new(),
        creation_time: 0,
        quorum: 1,
        signatures: Vec::new(),
    });
}
