//! Bounded real actor admission without socket or peer-writer execution.

use super::*;

/// Sole receiver owner for a test handle's actual bounded actor queues.
///
/// Admission still crosses `post_recoverable`, its wire checks, topology,
/// per-source FIFO and byte budgets. Draining proves actor acceptance, not a
/// peer-writer flush. Dropping this owner closes every actor queue.
pub struct NetworkActorAdmissionTestFixture<T> {
    receivers: [net_channel::Receiver<AdmittedNetworkMessage<T>>; 4],
}

impl<T> NetworkActorAdmissionTestFixture<T> {
    /// Inspect every admitted direct post while its real actor lease remains held.
    ///
    /// The fixture is the actor consumer: each inspected occurrence releases
    /// its queue and byte ownership before the next admission can retry.
    pub fn drain_posts(&mut self, mut inspect: impl FnMut(&Post<T>)) -> usize {
        let mut count = 0;
        for receiver in &mut self.receivers {
            while let Ok(admitted) = receiver.try_recv() {
                let (message, lease) = admitted.into_parts();
                let NetworkMessage::Post(post) = message else {
                    panic!("direct actor fixture received a broadcast occurrence");
                };
                inspect(&post);
                count += 1;
                drop(post);
                drop(lease);
            }
        }
        count
    }
}

impl<T: Pload + message::ClassifyTopic + Sync, E: Enc + Sync> NetworkBaseHandle<T, E> {
    /// Construct bounded live actor queues with exact direct topology for tests.
    ///
    /// This replaces only the closed fixture's queue endpoints and admission
    /// geometry. It does not install an admission hook or start socket tasks.
    #[must_use]
    pub fn actor_admission_for_tests(
        self_id: PeerId,
        targets: BTreeSet<PeerId>,
        capacity: std::num::NonZeroUsize,
    ) -> (Self, NetworkActorAdmissionTestFixture<T>) {
        let mut handle = Self::closed_for_tests();
        handle.self_id = self_id;
        let target_count = targets.len().max(1);
        // The bounded fixture has the same independent semantic waiter ranks
        // as production, including all Lane relay and exact-output producers.
        let waiters_per_target = actor_waiter_limits()
            .expect("bounded actor waiter classes")
            .into_iter()
            .try_fold(0usize, usize::checked_add)
            .expect("test actor waiter geometry fits usize");
        handle.network_actor_progress_budget = NetworkActorProgressBudget::new_classed(
            ActorProgressByteLimits::uniform(1024 * 1024),
            target_count,
            target_count
                .checked_mul(waiters_per_target)
                .expect("test waiter geometry fits usize"),
        )
        .expect("nonzero bounded test actor progress geometry");
        handle.network_actor_byte_budget =
            NetworkActorByteBudget::new(32 * 1024 * 1024, 1024 * 1024)
                .expect("bounded test actor bytes include the safety reserve");
        handle.network_actor_low_byte_budget = NetworkActorByteBudget::new(32 * 1024 * 1024, 0)
            .expect("bounded test actor low-priority bytes");
        let (safety_tx, safety_rx) = net_channel::channel_with_capacity(capacity.get());
        let (progress_tx, progress_rx) = net_channel::channel_with_capacity(capacity.get());
        let (high_tx, high_rx) = net_channel::channel_with_capacity(capacity.get());
        let (low_tx, low_rx) = net_channel::channel_with_capacity(capacity.get());
        handle.network_message_safety_sender = safety_tx;
        handle.network_message_progress_sender = progress_tx;
        handle.network_message_high_sender = high_tx;
        handle.network_message_low_sender = low_tx;
        let _ = handle
            .reliable_direct_topology
            .lock()
            .expect("isolated actor topology lock")
            .reconcile(&targets, &handle.self_id);
        (
            handle,
            NetworkActorAdmissionTestFixture {
                receivers: [safety_rx, progress_rx, high_rx, low_rx],
            },
        )
    }
}
