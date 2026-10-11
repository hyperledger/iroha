//! One successful native owner per Queue, with nonblocking original admission delivery.
//!
//! Startup reserves inline original identity/pool before attachment or driver launch. A
//! failed reservation releases only that ticket. After successful startup, retirement stops
//! notification but leaves permanent exclusion: workers may still be physically joining.
//! Ordinary restart uses a fresh Queue and the existing authenticated replay source. Weak
//! handles and the original charged wake retire outside queue guards; no bridge thread,
//! callback allocation, permission or new resource pool exists.

use super::Queue;
use crate::sumeragi::{driver, lanes::runner};
use iroha_allocation::AllocationBudget;
use std::sync::{Arc, Weak};

#[derive(Clone)]
pub(super) enum SumeragiQueueWake {
    Reserved {
        ticket: u64,
        budget: AllocationBudget,
    },
    Node {
        ticket: u64,
        budget: AllocationBudget,
        root: driver::QueueWake,
        lanes: runner::QueueWake,
    },
    Retired {
        budget: AllocationBudget,
    },
    // Preserve only the existing isolated queue probe, never native startup or shipping.
    #[cfg(test)]
    Probe(std::sync::mpsc::SyncSender<()>),
}

impl SumeragiQueueWake {
    pub(super) fn belongs_to(&self, original: &AllocationBudget) -> bool {
        match self {
            Self::Reserved { budget, .. }
            | Self::Node { budget, .. }
            | Self::Retired { budget } => budget.same_pool(original),
            #[cfg(test)]
            Self::Probe(_) => true,
        }
    }

    pub(super) fn notify(&self) {
        match self {
            Self::Node { root, lanes, .. } => {
                #[cfg(not(all(test, sumeragi_core_mutation = "HC189")))]
                root.notify();
                #[cfg(all(test, sumeragi_core_mutation = "HC189"))]
                let _ = root;
                #[cfg(not(all(test, sumeragi_core_mutation = "HC190")))]
                lanes.notify();
                #[cfg(all(test, sumeragi_core_mutation = "HC190"))]
                let _ = lanes;
            }
            Self::Reserved { .. } | Self::Retired { .. } => {}
            #[cfg(test)]
            Self::Probe(sender) => {
                let _ = sender.try_send(());
            }
        }
    }
}

/// Move-only startup ticket released only if the original native owner was not installed.
pub(crate) struct SumeragiQueueReservation {
    pub(super) queue: Weak<Queue>,
    pub(super) ticket: u64,
}

impl SumeragiQueueReservation {
    /// Bind the original weak runners to this exact prelaunch ticket and execution pool.
    /// Borrow the ticket so caller-owned partial workers retire before its failure cleanup.
    pub(crate) fn install(
        &self,
        root: driver::QueueWake,
        lanes: runner::QueueWake,
    ) -> Result<SumeragiQueueRegistration, &'static str> {
        let queue = self
            .queue
            .upgrade()
            .ok_or("original startup Queue retired")?;
        let retired = {
            let mut binding = queue.sumeragi_wake.lock();
            let Some(SumeragiQueueWake::Reserved { ticket, budget }) = binding.as_ref() else {
                return Err("original Queue startup reservation changed");
            };
            if *ticket != self.ticket || !root.belongs_to(budget) || !lanes.belongs_to(budget) {
                return Err("original Queue startup identity or pool changed");
            }
            let budget = budget.clone();
            binding.replace(SumeragiQueueWake::Node {
                ticket: self.ticket,
                budget,
                root,
                lanes,
            })
        };
        drop(retired);
        let registration = SumeragiQueueRegistration {
            queue: Arc::downgrade(&queue),
            ticket: self.ticket,
        };
        // Actual pre-binding admissions remain in their original Queue. One coalesced edge
        // requests their normal build; it never creates an idle/empty block.
        queue.wake_sumeragi();
        Ok(registration)
    }
}

impl Drop for SumeragiQueueReservation {
    fn drop(&mut self) {
        if let Some(queue) = self.queue.upgrade() {
            let retired = {
                let mut binding = queue.sumeragi_wake.lock();
                if matches!(binding.as_ref(), Some(SumeragiQueueWake::Reserved { ticket, .. }) if *ticket == self.ticket)
                {
                    binding.take()
                } else {
                    None
                }
            };
            drop(retired);
        }
    }
}

/// Retire delivery while permanently excluding reuse of this successful native Queue.
pub(crate) struct SumeragiQueueRegistration {
    pub(super) queue: Weak<Queue>,
    pub(super) ticket: u64,
}

impl Drop for SumeragiQueueRegistration {
    fn drop(&mut self) {
        if let Some(queue) = self.queue.upgrade() {
            // Retire under the same fence as the last admission check/publication. Existing
            // residents stay owned for inspection/refund, but no new admission can pass
            // after its successful native owner has permanently retired.
            queue.with_resident_refunds(
                || {
                    let mut binding = queue.sumeragi_wake.lock();
                    if let Some(SumeragiQueueWake::Node { ticket, budget, .. }) = binding.as_ref() {
                        if *ticket == self.ticket {
                            let budget = budget.clone();
                            binding.replace(SumeragiQueueWake::Retired { budget })
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                },
                |retired| {
                    // Last original charged wake/input owners retire outside both locks.
                    // Permanent exclusion also covers callback-transferred physical joins.
                    drop(retired);
                },
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_primitives::time::TimeSource;
    use std::time::Duration;

    #[test]
    fn failed_startup_reservation_releases_only_its_exact_original_ticket() {
        let (_, time) = TimeSource::new_mock(Duration::ZERO);
        let queue = Arc::new(Queue::test(
            iroha_config::parameters::actual::Queue::default(),
            &time,
        ));
        let pool = AllocationBudget::new(1024 * 1024);
        let first = queue.reserve_sumeragi_start(&pool).unwrap();
        let old_ticket = first.ticket;
        assert!(matches!(
            queue.reserve_sumeragi_start(&pool),
            Err(
                "transaction queue already has an original native owner; restart with a fresh Queue"
            )
        ));
        drop(first);
        let next = queue.reserve_sumeragi_start(&pool).unwrap();
        assert_ne!(old_ticket, next.ticket);
        // Private-path adversary: late retirement of a stale ticket cannot clear the real next owner.
        drop(SumeragiQueueReservation {
            queue: Arc::downgrade(&queue),
            ticket: old_ticket,
        });
        assert!(matches!(queue.sumeragi_wake.lock().as_ref(),
            Some(SumeragiQueueWake::Reserved { ticket, .. }) if *ticket == next.ticket));
        drop(next);
        assert!(queue.sumeragi_wake.lock().is_none());
        assert_eq!(
            pool.reserved_bytes(),
            0,
            "reservation creates no allocation or charge"
        );
    }

    #[test]
    fn reserved_original_pool_refuses_foreign_resident_admission_before_allocation() {
        let (_, time) = TimeSource::new_mock(Duration::ZERO);
        let queue = Arc::new(Queue::test(
            iroha_config::parameters::actual::Queue::default(),
            &time,
        ));
        let pool = AllocationBudget::new(1024 * 1024);
        let foreign = AllocationBudget::new(pool.limit_bytes());
        let reservation = queue.reserve_sumeragi_start(&pool).unwrap();
        let guard = queue.push_remove_lock.lock();
        let error = match queue.resident_ledger(&foreign) {
            Ok(_) => panic!("foreign cold admission must not allocate original resident custody"),
            Err(error) => error,
        };
        drop(guard);
        assert!(
            matches!(error, crate::queue::Error::AdmissionInvariant { ref reason }
            if reason == "Queue resident custody belongs to a different original State pool")
        );
        assert!(queue.resident_accounting.get().is_none());
        assert_eq!(foreign.reserved_bytes(), 0);
        assert_eq!(pool.reserved_bytes(), 0);
        drop(reservation);
    }

    #[test]
    fn root_only_durable_wake_preserves_reserved_and_retired_queue_custody() {
        let (_, time) = TimeSource::new_mock(Duration::ZERO);
        let queue = Arc::new(Queue::test(
            iroha_config::parameters::actual::Queue::default(),
            &time,
        ));
        let pool = AllocationBudget::new(1024 * 1024);
        let foreign = AllocationBudget::new(pool.limit_bytes());
        let ticket = queue.reserve_sumeragi_start(&pool).unwrap();
        assert!(queue.belongs_to_sumeragi_pool(&pool));
        assert!(!queue.belongs_to_sumeragi_pool(&foreign));
        queue.wake_sumeragi_root(&pool);
        assert!(matches!(queue.sumeragi_wake.lock().as_ref(),
            Some(SumeragiQueueWake::Reserved { ticket: current, .. }) if *current == ticket.ticket));
        drop(ticket);
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        queue.set_sumeragi_wake(sender);
        queue.wake_sumeragi_root(&pool);
        receiver
            .try_recv()
            .expect("existing isolated root probe observes the durable notification");
        let old = queue
            .sumeragi_wake
            .lock()
            .replace(SumeragiQueueWake::Retired {
                budget: pool.clone(),
            });
        drop(old);
        assert!(!queue.belongs_to_sumeragi_pool(&pool));
        queue.wake_sumeragi_root(&pool);
        assert!(matches!(
            receiver.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Disconnected)
        ));
        assert!(matches!(
            queue.sumeragi_wake.lock().as_ref(),
            Some(SumeragiQueueWake::Retired { .. })
        ));
        assert_eq!(pool.reserved_bytes(), 0);
        assert_eq!(foreign.reserved_bytes(), 0);
    }
}
