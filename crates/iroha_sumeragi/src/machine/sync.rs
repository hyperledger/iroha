//! Catch-up (sync), block-body wants and serving (§6.9).

use std::collections::BTreeMap;

use super::{Core, MAX_WANTS, Via, Want};
use crate::{
    api::Action,
    availability::{AvailabilitySource, AvailableBody},
    message::{PayloadManifest, Qc, SyncEntry, SyncRequest, SyncResponse, VoteKind, WireMessage},
    types::{Hash32, PublicKey},
};

/// Largest number of remembered sync sources.
const MAX_SOURCES: usize = 64;

/// Sync state (§6.9): one outstanding request, a bounded buffer of verified-shape entries.
#[derive(Clone, Debug, Default)]
pub(super) struct SyncState {
    /// Highest height known (by a verified `CommitQC`) to be committed.
    verified: u64,
    /// Highest height hinted by an unverifiable `CommitQC` from a member of `C_h`.
    hint: u64,
    sources: Vec<PublicKey>,
    rotate: usize,
    /// `(peer, from_height, deadline)` of the outstanding request.
    outstanding: Option<(PublicKey, u64, u64)>,
    /// Unanswered requests `(peer, from_height)`, oldest first (bounded). Each is answered by
    /// at most one response, whenever it arrives, also after the request was retried
    /// elsewhere (§6.9 rule 3).
    asked: Vec<(PublicKey, u64)>,
    /// Sources that answered the hint with nothing, consecutively.
    empty_from: Vec<PublicKey>,
    pub(super) buffer: BTreeMap<u64, SyncEntry>,
    pub(super) buffer_bytes: usize,
}

impl SyncState {
    /// `sync.target` (0 = none).
    pub(super) fn target(&self) -> u64 {
        self.verified.max(self.hint)
    }

    /// The verified part of the target: only it makes a node unsettled (§6.9 rule 1, §6.11).
    pub(super) fn verified_target(&self) -> u64 {
        self.verified
    }

    fn note_asked(&mut self, key: &PublicKey, from_height: u64) {
        let request = (key.clone(), from_height);
        if !self.asked.contains(&request) {
            if self.asked.len() >= MAX_SOURCES {
                self.asked.remove(0);
            }
            self.asked.push(request);
        }
    }

    /// Take the unanswered request of `peer` that a response answers: the one from the
    /// response's first height, or (an empty response) the peer's latest. Returns its
    /// `from_height`; `None` = the response answers no request of this node.
    fn take_request(&mut self, peer: &PublicKey, first: Option<u64>) -> Option<u64> {
        let position = match first {
            Some(height) => self
                .asked
                .iter()
                .position(|(key, from)| key == peer && *from == height),
            None => self.asked.iter().rposition(|(key, _)| key == peer),
        }?;
        Some(self.asked.remove(position).1)
    }

    fn add_source(&mut self, key: &PublicKey) {
        if !self.sources.contains(key) {
            if self.sources.len() >= MAX_SOURCES {
                self.sources.remove(0);
            }
            self.sources.push(key.clone());
        }
    }

    /// The peer of the outstanding request (tests).
    #[cfg(test)]
    pub(super) fn outstanding_peer(&self) -> Option<PublicKey> {
        self.outstanding.as_ref().map(|(peer, _, _)| peer.clone())
    }

    /// Deadline of the outstanding request.
    pub(super) fn deadline(&self) -> Option<u64> {
        self.outstanding.as_ref().map(|(_, _, deadline)| *deadline)
    }
}

/// Approximate buffered size of an entry (payload plus a header allowance).
// SPEC: §8.4 bounds the buffer by `2·sync_max_bytes` without fixing how an entry is measured; the
// payload plus a fixed allowance per header and skipped leader is used (no re-encoding).
// (Appendix E, E26)
fn entry_bytes(entry: &SyncEntry) -> usize {
    entry
        .manifest
        .availability
        .as_slice()
        .len()
        .saturating_add(256 + crate::types::MAX_CONTROL_WITNESS_BYTES)
        .saturating_add(
            entry
                .manifest
                .header
                .skipped_leaders
                .len()
                .saturating_mul(64),
        )
}

impl Core {
    /// The first height this node has not committed.
    fn next_height(&self) -> u64 {
        self.tip.height.saturating_add(1)
    }

    /// §6.9 rule 1: a `CommitQC` for a height above the current round's.
    pub(super) fn sync_hint(&mut self, c: &Qc, from: &PublicKey) {
        if c.kind != VoteKind::Commit || c.height <= self.height || c.height <= self.tip.height {
            return;
        }
        if c.height <= self.sync.verified {
            self.sync.add_source(from);
            return;
        }
        if self.config(c.height).is_some() {
            if self.verify_qc_cached(c) {
                self.sync.verified = c.height;
                self.sync.add_source(from);
            }
        } else if self.cfg.committee.contains(from) {
            if c.height > self.sync.hint {
                self.sync.hint = c.height;
                self.sync.empty_from.clear();
            }
            self.sync.add_source(from);
        }
        self.maybe_request_sync();
    }

    /// §6.9 rule 2: keep exactly one request outstanding while behind.
    pub(super) fn maybe_request_sync(&mut self) {
        let next = self.next_height();
        if self.sync.outstanding.is_some() || self.sync.target() < next {
            if self.sync.target() < next {
                self.sync.verified = 0;
                self.sync.hint = 0;
            }
            return;
        }
        #[cfg(not(sumeragi_mutation = "ME3"))]
        self.keep_buffer_contiguous(next);
        if self.sync.buffer.len() >= usize::from(self.local.sync_batch) {
            return;
        }
        let from_height = self
            .sync
            .buffer
            .last_key_value()
            .map_or(next, |(h, _)| h.saturating_add(1))
            .max(next);
        if from_height > self.sync.target() {
            return;
        }
        let mut candidates = self.sync.sources.clone();
        for (key, peer) in &self.peers {
            // §6.9 rule 2: members whose `Status` shows a higher height (not observers).
            if peer.height > next && self.cfg.committee.contains(key) && !candidates.contains(key) {
                candidates.push(key.clone());
            }
        }
        if candidates.is_empty() {
            return;
        }
        // Rotate to the next source on every request (§6.9 rule 2).
        let to = candidates[self.sync.rotate % candidates.len()].clone();
        self.sync.rotate = self.sync.rotate.wrapping_add(1);
        self.sync.note_asked(&to, from_height);
        let msg = WireMessage::SyncRequest(SyncRequest {
            instance: self.instance,
            from_height,
            max_count: self.local.sync_batch,
            max_bytes: self.local.sync_max_bytes,
        });
        self.sync.outstanding = Some((
            to.clone(),
            from_height,
            self.now.saturating_add(self.local.sync_retry),
        ));
        self.send(to, msg);
    }

    /// Drop buffered entries above a gap in the heights from `next` on.
    // SPEC: §6.9 rule 2 requests from `max(h, highest buffered height + 1)`, which assumes the
    // buffer is contiguous from `h`. When an invalid entry is dropped at its turn (rule 3) after
    // the next request went out, the answer to that request is buffered above a gap that is
    // never requested again, and a full buffer blocks every further request: catch-up stops for
    // good (found by the simulator: F17 seed 106, a Byzantine responder rewriting the result of
    // its CommitQCs). Entries beyond a gap are dropped and fetched again (Appendix E, E3).
    fn keep_buffer_contiguous(&mut self, next: u64) {
        let cut = self
            .sync
            .buffer
            .range(next..)
            .zip(std::iter::successors(Some(next), |height| {
                height.checked_add(1)
            }))
            .find_map(|((height, _), expected)| (*height != expected).then_some(*height));
        if let Some(cut) = cut {
            let dropped = self.sync.buffer.split_off(&cut);
            let bytes: usize = dropped.values().map(entry_bytes).sum();
            self.sync.buffer_bytes = self.sync.buffer_bytes.saturating_sub(bytes);
        }
    }

    /// Sync retry deadline passed: rotate to another source.
    pub(super) fn sync_tick(&mut self) {
        if let Some((peer, _, deadline)) = self.sync.outstanding.clone()
            && self.now >= deadline
        {
            self.sync.outstanding = None;
            // SPEC: an unanswered request counts like an empty response for dropping an
            // unverified hint (a silent source would otherwise keep a bogus hint and its
            // requests alive forever; Appendix E, E3).
            self.note_empty(&peer);
            self.maybe_request_sync();
        }
    }

    fn note_empty(&mut self, peer: &PublicKey) {
        if self.sync.hint <= self.sync.verified {
            return;
        }
        if !self.sync.empty_from.contains(peer) {
            self.sync.empty_from.push(peer.clone());
        }
        if self.sync.empty_from.len() >= 2 {
            self.sync.hint = 0;
            self.sync.empty_from.clear();
        }
    }

    /// `on_sync_response` (§6.9 rule 3): processed whenever it arrives, as the answer to one
    /// unanswered `SyncRequest` of this node to that peer (also after the request was retried
    /// elsewhere); other responses are dropped. Entries below `h` are skipped; the others must
    /// be well formed and of consecutive heights (the first failing entry is dropped with the
    /// rest). An empty response counts as empty for dropping an unverified target (rule 1).
    // SPEC: §6.9 rule 3 processes every response of a peer that was ever sent a request and
    // never replaces a buffered entry, so one Byzantine source asked once could keep sending
    // well-formed entries with forged CommitQCs for the heights above `h`: they filled the
    // buffer, never reached their turn (no entry at `h`), and every honest answer found the
    // buffer full, so a lagging node never caught up (found by review). A response now answers
    // exactly one unanswered request to that peer and starts at its `from_height` (honest
    // serving always does, rule 4); buffered entries above a gap are dropped before it is
    // checked; and only members count as `Status` candidates (rule 2). A forged entry thus
    // reaches its turn and is dropped there, at most once per request sent to its source
    // (Appendix E, E36).
    pub(super) fn on_sync_response(&mut self, from: &PublicKey, response: SyncResponse) {
        // MR-sync-late: only the peer of the outstanding request is heard.
        #[cfg(sumeragi_mutation = "MR-sync-late")]
        if (self.sync.outstanding.as_ref()).is_none_or(|(peer, _, _)| peer != from) {
            return;
        }
        let first = response.blocks.first().map(|entry| entry.commit_qc.height);
        let Some(from_height) = self.sync.take_request(from, first) else {
            return;
        };
        if self
            .sync
            .outstanding
            .as_ref()
            .is_some_and(|(peer, height, _)| peer == from && *height == from_height)
        {
            self.sync.outstanding = None;
        }
        #[cfg(not(sumeragi_mutation = "ME3"))]
        self.keep_buffer_contiguous(self.next_height());
        let mut previous: Option<u64> = None;
        let mut useful = false;
        let max_entries = 2 * usize::from(self.local.sync_batch);
        let max_bytes = 2 * usize::try_from(self.local.sync_max_bytes).unwrap_or(usize::MAX);
        for entry in response.blocks {
            let qc = &entry.commit_qc;
            let well_formed = qc.kind == VoteKind::Commit
                && qc.height == entry.manifest.header.height
                && previous.is_none_or(|p| Some(qc.height) == p.checked_add(1))
                && (entry.manifest.hash(&*self.crypto) == qc.block_hash
                    || cfg!(sumeragi_mutation = "MS22"))
                && entry.manifest.availability.has_valid_structure();
            if !well_formed {
                break;
            }
            previous = Some(qc.height);
            useful = true;
            let bytes = entry_bytes(&entry);
            if qc.height < self.next_height() || self.sync.buffer.contains_key(&qc.height) {
                continue;
            }
            if self.sync.buffer.len() >= max_entries
                || self.sync.buffer_bytes.saturating_add(bytes) > max_bytes
            {
                break;
            }
            self.sync.buffer_bytes = self.sync.buffer_bytes.saturating_add(bytes);
            self.sync.buffer.insert(qc.height, entry);
        }
        if useful {
            self.sync.add_source(from);
            self.sync.empty_from.clear();
        } else {
            self.note_empty(from);
        }
    }

    /// Commit buffered entries in height order (§6.9 rule 3): the entry for the current height
    /// needs a verified `CommitQC` under `C_h` and the parent link (SR22).
    pub(super) fn process_sync_buffer(&mut self) {
        loop {
            let next = self.next_height();
            let pending = self.sync.buffer.split_off(&next);
            let stale = std::mem::replace(&mut self.sync.buffer, pending);
            let bytes: usize = stale.values().map(entry_bytes).sum();
            self.sync.buffer_bytes = self.sync.buffer_bytes.saturating_sub(bytes);
            if self.awaiting || self.halted.is_some() || self.height != next {
                return;
            }
            let Some(entry) = self.sync.buffer.remove(&next) else {
                return;
            };
            self.sync.buffer_bytes = self.sync.buffer_bytes.saturating_sub(entry_bytes(&entry));
            let header = &entry.manifest.header;
            let linked = cfg!(sumeragi_mutation = "MS22")
                || (header.parent_hash == self.tip.block_hash
                    && header.parent_result == self.tip.result
                    && header.epoch == self.cfg.epoch.id);
            #[cfg(not(sumeragi_mutation = "MS15"))]
            let committee = &self.cfg.committee;
            #[cfg(sumeragi_mutation = "MS15")]
            let committee = &(self.config(self.tip.height).unwrap_or(&self.cfg)).committee;
            let verified = self
                .cert_cache
                .contains(&entry.commit_qc.digest(&*self.crypto))
                || crate::crypto::Verifier::new(
                    &*self.crypto,
                    &self.instance,
                    &self.cfg.epoch.id,
                    committee,
                )
                .verify_qc(&entry.commit_qc)
                .is_ok();
            if !linked || !verified {
                self.sync.buffer.clear();
                self.sync.buffer_bytes = 0;
                return;
            }
            let bh = entry.commit_qc.block_hash;
            if !self.blocks.contains_key(&bh) {
                let manifest = entry.manifest.clone();
                self.sync.buffer_bytes = self.sync.buffer_bytes.saturating_add(entry_bytes(&entry));
                self.sync.buffer.insert(next, entry);
                if !self.wants.contains_key(&bh) {
                    self.want(bh, next, self.sync.sources.clone());
                }
                self.on_manifest(manifest);
                return;
            }
            self.commit_height(entry.commit_qc, Via::Sync);
        }
    }

    /// Create (or extend the sources of) a want for a body (§6.9 rule 5), and fetch at once.
    pub(super) fn want(&mut self, bh: Hash32, height: u64, sources: Vec<PublicKey>) {
        if self.blocks.contains_key(&bh) {
            return;
        }
        let limit = self.n().saturating_add(8);
        if let Some(want) = self.wants.get_mut(&bh) {
            for key in sources {
                if !want.sources.contains(&key) && want.sources.len() < limit {
                    want.sources.push(key);
                }
            }
            return;
        }
        if self.wants.len() >= MAX_WANTS {
            return;
        }
        let mut unique: Vec<PublicKey> = Vec::new();
        for key in sources.into_iter().chain(self.status_reporters(&bh)) {
            if !unique.contains(&key) && !self.is_local_key(&key) && unique.len() < limit {
                unique.push(key);
            }
        }
        self.wants.insert(
            bh,
            Want {
                height,
                sources: unique,
                cursor: 0,
                attempt: 0,
                next_retry: self.now,
            },
        );
        self.fetch(bh);
    }

    /// `FetchBody` with the next `min(2^(attempt+1), |sources|)` sources (cyclic).
    fn fetch(&mut self, bh: Hash32) {
        let now = self.now;
        let retry = self.local.fetch_retry;
        let Some(want) = self.wants.get_mut(&bh) else {
            return;
        };
        let len = want.sources.len();
        let count = 1usize
            .checked_shl(want.attempt.saturating_add(1))
            .unwrap_or(usize::MAX)
            .min(len);
        #[cfg(not(sumeragi_mutation = "MR-fetch-cycle"))]
        let cursor = want.cursor;
        #[cfg(sumeragi_mutation = "MR-fetch-cycle")]
        let cursor = 0;
        let peers: Vec<PublicKey> = (0..count)
            .filter_map(|i| want.sources.get((cursor + i) % len.max(1)).cloned())
            .collect();
        want.cursor = if len == 0 {
            0
        } else {
            (want.cursor + count) % len
        };
        want.attempt = want.attempt.saturating_add(1);
        want.next_retry = now.saturating_add(retry);
        let height = want.height;
        let Some(config) = self.config(height).cloned() else {
            return;
        };
        let Ok(source) = AvailabilitySource::new(self.instance, height, bh, config) else {
            return;
        };
        self.out.push(Action::FetchPayload { source, peers });
    }

    /// Fetch retries that are due (§6.11).
    pub(super) fn fetch_tick(&mut self) {
        let due: Vec<Hash32> = self
            .wants
            .iter()
            .filter(|(_, want)| want.next_retry <= self.now)
            .map(|(bh, _)| *bh)
            .collect();
        for bh in due {
            self.fetch(bh);
        }
    }

    /// Members whose latest `Status` reported `bh` as their proposal.
    pub(super) fn status_reporters(&self, bh: &Hash32) -> Vec<PublicKey> {
        self.peers
            .iter()
            .filter(|(_, peer)| peer.proposal_hash.as_ref() == Some(bh))
            .map(|(key, _)| key.clone())
            .collect()
    }

    /// `on_body` (§6.9 rule 6): only wanted custody of the exact independently selected
    /// full authority and original pool (SR20); a held body is never replaced. Then the
    /// `pending_apply` flush (with its parent-link check) and whatever waited for the body.
    pub(super) fn on_body(&mut self, block: AvailableBody) {
        let bh = block.hash(&*self.crypto);
        let Some(want) = self.wants.get(&bh) else {
            return;
        };
        if block.header().height != want.height
            || !block.admitted_to(&self.body_budget)
            || block.source().instance() != self.instance
            || self
                .config(want.height)
                .is_none_or(|config| block.source().config() != config)
        {
            return;
        }
        self.put_body(bh, block);
        self.after_body(bh);
    }

    /// Continue whatever waited for the body of `bh`.
    pub(super) fn after_body(&mut self, bh: Hash32) {
        self.flush_pending_apply();
        if self.halted.is_some() || self.awaiting {
            return;
        }
        let h0 = self.height;
        if self.proposal.as_ref().is_some_and(|held| held.bh == bh) {
            self.maybe_execute();
            if !self.same_height(h0) {
                return;
            }
        }
        if self.resend_recorded == Some(bh) {
            self.resend_recorded_proposal();
            if !self.same_height(h0) {
                return;
            }
        }
        let reproposal = self
            .high_tc
            .as_ref()
            .and_then(|tc| tc.high_pqc.as_ref())
            .is_some_and(|q| q.block_hash == bh);
        if self.repropose && reproposal {
            self.try_repropose();
        }
    }

    /// Serve a `SyncRequest` (§6.9 rule 4); per-peer rate limits are the driver's.
    pub(super) fn serve_sync(&mut self, to: PublicKey, request: &SyncRequest) {
        self.out.push(Action::ServeBlocks {
            to,
            from_height: request.from_height,
            max_count: request.max_count.min(self.local.sync_batch),
            max_bytes: request.max_bytes.min(self.local.sync_max_bytes),
        });
    }
    pub(super) fn on_manifest_rejected(&mut self, manifest: &PayloadManifest) {
        // Rejected unsigned carrier bytes do not prove a signed leader defect (SR35).
        #[cfg(sumeragi_mutation = "MS35")]
        if self
            .proposal
            .as_ref()
            .is_some_and(|held| held.bh == manifest.hash(&*self.crypto) && held.p.view == self.view)
        {
            self.sign_timeout(self.view);
        }
        let height = manifest.header.height;
        if self
            .sync
            .buffer
            .get(&height)
            .is_some_and(|entry| &entry.manifest == manifest)
        {
            let removed = self
                .sync
                .buffer
                .remove(&height)
                .expect("exact rejected entry");
            self.sync.buffer_bytes = self.sync.buffer_bytes.saturating_sub(entry_bytes(&removed));
            self.keep_buffer_contiguous(self.next_height());
            self.maybe_request_sync();
        }
    }
}
