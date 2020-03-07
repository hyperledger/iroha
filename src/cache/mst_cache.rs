use std::fmt;
use crate::model::model;

pub struct MSTCache {
    waiting_mst_tx: Vec<model::Transaction>
}

impl MSTCache {
    // constructor
    pub fn new() -> MSTCache {
        MSTCache {
            waiting_mst_tx: Vec::new()
        }
    }
}

impl fmt::Display for MSTCache {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.waiting_mst_tx)//TODO:
    }
}
