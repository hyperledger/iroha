use std::fmt;
use crate::model::model;

#[derive(Default)]
pub struct MSTCache {
    waiting_mst_tx: Vec<model::Transaction>
}

impl fmt::Display for MSTCache {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.waiting_mst_tx)//TODO:
    }
}
