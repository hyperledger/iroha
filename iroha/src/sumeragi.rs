use crate::prelude::*;

#[derive(Default)]
pub struct Sumeragi {}

impl Sumeragi {
    pub fn new() -> Self {
        Sumeragi {}
    }

    pub async fn sign(
        &mut self,
        transactions: Vec<Transaction>,
    ) -> Result<Vec<Transaction>, String> {
        Ok(transactions
            .into_iter()
            .map(|tx| tx.sign(Vec::new()))
            .filter_map(Result::ok)
            .collect())
    }
}
