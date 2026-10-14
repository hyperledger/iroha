//! Central authenticated-session arbitration before any per-PeerId reader bind.
//! Entries are admitted only for the network's existing capped connection ids.
//! Both endpoints order the full identity-authenticated session hash identically.
use crate::peer::{ConnectionId, message::Authenticated, tenure::ReaderPermit};
use iroha_model_base::peer::PeerId;
use std::{
    collections::{BTreeMap, HashMap},
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::sync::{oneshot, watch};

struct Entry {
    peer: PeerId,
    session: [u8; iroha_crypto::Hash::LENGTH],
    cancel: watch::Sender<bool>,
    reply: Option<oneshot::Sender<ReaderPermit>>,
    released: Option<oneshot::Receiver<()>>,
    connected: bool,
}
/// Admission outcome and the predecessor still charged until its termination.
pub(super) struct Admission {
    pub(super) accepted: bool,
    pub(super) retired: Option<ConnectionId>,
}
/// One process-local arbiter, owned and polled only by `NetworkBase`.
#[derive(Default)]
pub(super) struct Arbitration {
    entries: BTreeMap<ConnectionId, Entry>,
    selected: HashMap<PeerId, ConnectionId>,
}
impl Arbitration {
    /// Admit a verified, already connection-count-reserved identity.
    pub(super) fn admit(&mut self, candidate: Authenticated) -> Admission {
        let Authenticated {
            peer,
            connection_id,
            session,
            cancel,
            reply,
            ..
        } = candidate;
        if reply.is_closed() || *cancel.borrow() || self.entries.contains_key(&connection_id) {
            cancel.send_replace(true);
            return Admission {
                accepted: false,
                retired: None,
            };
        }
        let closed_selection = self.selected.get(peer.id()).copied().filter(|id| {
            let entry = &self.entries[id];
            *entry.cancel.borrow() || entry.reply.as_ref().is_some_and(oneshot::Sender::is_closed)
        });
        if let Some(id) = closed_selection {
            self.cancel(id);
        }
        // A queued release must not let an already dead higher session reject
        // the current peer merely because the actor's global drain budget ended.
        // Each pass removes one existing entry. Granting a waiting successor
        // can immediately fail if its receiver closed, so drain that release
        // too before comparing ranks; this cannot add entries or reset time.
        loop {
            let released = self.entries.iter_mut().find_map(|(&id, entry)| {
                if &entry.peer != peer.id() {
                    return None;
                }
                entry
                    .released
                    .as_mut()
                    .and_then(|receiver| match receiver.try_recv() {
                        Ok(()) | Err(oneshot::error::TryRecvError::Closed) => Some(id),
                        Err(oneshot::error::TryRecvError::Empty) => None,
                    })
            });
            let Some(id) = released else {
                break;
            };
            self.released(id);
        }
        let prior = self.selected.get(peer.id()).copied();
        if let Some(prior_id) = prior {
            let old = &self.entries[&prior_id];
            if old.session > session {
                cancel.send_replace(true);
                return Admission {
                    accepted: false,
                    retired: None,
                };
            }
            if old.session == session {
                // Never break a complete-session tie with local ids or direction.
                cancel.send_replace(true);
                self.cancel(prior_id);
                return Admission {
                    accepted: false,
                    retired: Some(prior_id),
                };
            }
            self.cancel(prior_id);
        }
        let peer_id = peer.id().clone();
        self.entries.insert(
            connection_id,
            Entry {
                peer: peer_id.clone(),
                session,
                cancel,
                reply: Some(reply),
                released: None,
                connected: false,
            },
        );
        self.selected.insert(peer_id.clone(), connection_id);
        self.grant_if_released(&peer_id);
        Admission {
            accepted: true,
            retired: prior,
        }
    }
    /// Cancellation never releases an issued reader permit early.
    pub(super) fn cancel(&mut self, id: ConnectionId) {
        let Some(entry) = self.entries.get_mut(&id) else {
            return;
        };
        entry.cancel.send_replace(true);
        entry.reply.take();
        if self.selected.get(&entry.peer) == Some(&id) {
            self.selected.remove(&entry.peer);
        }
        if entry.released.is_none() {
            self.entries.remove(&id);
        }
    }
    fn grant_if_released(&mut self, peer: &PeerId) {
        if self
            .entries
            .values()
            .any(|entry| &entry.peer == peer && entry.released.is_some())
        {
            return;
        }
        let Some(id) = self.selected.get(peer).copied() else {
            return;
        };
        let Some(entry) = self.entries.get_mut(&id) else {
            return;
        };
        let Some(reply) = entry.reply.take() else {
            return;
        };
        if reply.is_closed() {
            self.cancel(id);
            return;
        }
        let (permit, released) = ReaderPermit::channel();
        // Observe release before publishing permission. A receiver cancelled
        // during send drops this same permit, waking the connection owner.
        entry.released = Some(released);
        if reply.send(permit).is_err() {
            self.cancel(id);
        }
    }
    /// Drain ready release notifications with the actor's existing service budget.
    pub(super) fn ready_release(&mut self) -> Option<ConnectionId> {
        self.entries.iter_mut().find_map(|(&id, entry)| {
            entry
                .released
                .as_mut()
                .and_then(|receiver| match receiver.try_recv() {
                    Ok(()) | Err(oneshot::error::TryRecvError::Closed) => Some(id),
                    Err(oneshot::error::TryRecvError::Empty) => None,
                })
        })
    }
    /// Wake from physical reader completion, independent of final consumers.
    pub(super) fn poll_released(&mut self, cx: &mut Context<'_>) -> Poll<ConnectionId> {
        for (&id, entry) in &mut self.entries {
            if let Some(released) = &mut entry.released
                && Pin::new(released).poll(cx).is_ready()
            {
                return Poll::Ready(id);
            }
        }
        Poll::Pending
    }
    /// Retire exactly one physical reader and permit its selected successor.
    pub(super) fn released(&mut self, id: ConnectionId) {
        let Some(entry) = self.entries.remove(&id) else {
            return;
        };
        if self.selected.get(&entry.peer) == Some(&id) {
            self.selected.remove(&entry.peer);
        }
        self.grant_if_released(&entry.peer);
    }
    /// Accept one Connected notice only from the current issued reader.
    pub(super) fn claim_connected(
        &mut self,
        id: ConnectionId,
        peer: &PeerId,
        compact: u64,
    ) -> bool {
        if self.selected.get(peer) != Some(&id) {
            return false;
        }
        let Some(entry) = self.entries.get_mut(&id) else {
            return false;
        };
        let mut prefix = [0; 8];
        prefix.copy_from_slice(&entry.session[..8]);
        let reader_live = entry.released.as_mut().is_some_and(|released| {
            matches!(
                released.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            )
        });
        if entry.connected
            || !reader_live
            || *entry.cancel.borrow()
            || entry.peer != *peer
            || u64::from_be_bytes(prefix) != compact
        {
            return false;
        }
        entry.connected = true;
        true
    }
}
impl Drop for Arbitration {
    fn drop(&mut self) {
        for entry in self.entries.values() {
            entry.cancel.send_replace(true);
        }
    }
}

#[cfg(test)]
mod tests;

/// Native test adapter to this exact actor owner; it contains no alternate policy.
#[cfg(test)]
pub mod fixture {
    use super::*;
    #[derive(Default)]
    pub struct Owner(Arbitration);
    impl Owner {
        pub(crate) fn admit(&mut self, candidate: Authenticated) -> bool {
            self.0.admit(candidate).accepted
        }
        pub(crate) fn drain(&mut self) {
            while let Some(id) = self.0.ready_release() {
                self.0.released(id);
            }
        }
        pub(crate) fn claim(&mut self, id: ConnectionId, peer: &PeerId, compact: u64) -> bool {
            self.0.claim_connected(id, peer, compact)
        }
    }
}
