use std::fmt;
use crate::model::model;

pub struct MST_Cache {
    waiting_mst_tx: Vec<model::Transaction>
}

impl MST_Cache {
    // constructor
    pub fn new() -> MST_Cache {
        MST_Cache {
            waiting_mst_tx: Vec::new()
        }
    }
}

impl fmt::Display for MST_Cache {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.waiting_mst_tx)//TODO:
    }
}
