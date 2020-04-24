use crate::prelude::*;

#[derive(Default)]
pub struct Queue {
    pending_tx: Vec<Transaction>,
}

impl Queue {
    pub fn push_pending_transaction(&mut self, tx: Transaction) {
        self.pending_tx.push(tx);
    }

    pub fn pop_pending_transactions(&mut self) -> Vec<Transaction> {
        self.pending_tx.drain(..).collect()
    }

    pub fn get_pending_transactions(&self) -> &[Transaction] {
        &self.pending_tx
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;

    #[test]
    fn push_pending_transaction() {
        let (public_key, private_key) =
            crypto::generate_key_pair().expect("Failed to generate key pair.");
        let mut queue = Queue::default();
        queue.push_pending_transaction(
            Transaction::new(
                Vec::new(),
                Id::new("account", "domain"),
                &public_key,
                &private_key,
            )
            .expect("Failed to create Transaction."),
        );
    }
}
