use crate::prelude::*;

#[derive(Default, Debug)]
pub struct Queue {
    pending_tx: Vec<AcceptedTransaction>,
}

impl Queue {
    pub fn push_pending_transaction(&mut self, tx: AcceptedTransaction) {
        self.pending_tx.push(tx);
    }

    pub fn pop_pending_transactions(&mut self) -> Vec<AcceptedTransaction> {
        self.pending_tx.drain(..).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_pending_transaction() {
        let mut queue = Queue::default();
        queue.push_pending_transaction(
            RequestedTransaction::new(
                Vec::new(),
                <Account as Identifiable>::Id::new("account", "domain"),
            )
            .accept()
            .expect("Failed to create Transaction."),
        );
    }
}
