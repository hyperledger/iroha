use crate::model::tx::Transaction;
use std::fmt::{Display, Formatter, Result};

#[derive(Default)]
pub struct MSTCache {
    waiting_mst_tx: Vec<Transaction>,
}

impl Display for MSTCache {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "{:?}", self.waiting_mst_tx) //TODO:
    }
}
