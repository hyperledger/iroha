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

/// Architecture-independent allowance for both responder records and the optional full QC.
/// Native record sizes are checked below; heap bitmap/key bounds are reserved separately.
const SYNC_DONOR_RECORD_ALLOWANCE: usize = 512;
/// Reserve the complete alternate slot at initial admission, even before any donor refresh.
const SYNC_DONOR_RESERVATION: usize = SYNC_DONOR_RECORD_ALLOWANCE
    + crate::message::MAX_BITMAP_BYTES
    + 2 * crate::types::MAX_PUBLIC_KEY_LEN;
/// Architecture-independent allowance for a buffered entry's inline fields beyond its canonical
/// bytes, including the full inline control-witness capacity held even for an empty witness.
/// The native entry size is checked below. The buffer's byte bound is on these charges: the
/// map's unused leaf slots and allocator rounding are not charged and grow only with the entry
/// count, which `2·sync_batch` bounds.
const SYNC_ENTRY_NATIVE_ALLOWANCE: usize = 1024 + crate::types::MAX_CONTROL_WITNESS_BYTES;
/// Allowance for each skipped leader's native key record beyond its canonical key bytes.
const SYNC_SKIPPED_LEADER_NATIVE_ALLOWANCE: usize = 64;

/// One requested sync carrier and its exact authenticated transport responder.
#[derive(Clone, Debug)]
pub(super) struct BufferedSyncEntry {
    entry: SyncEntry,
    responder: PublicKey,
    deferred: Option<DeferredSyncDonor>,
    /// Buffer charge fixed at admission ([`entry_bytes`]); exactly this is refunded on removal.
    charge: usize,
}

/// At most one alternative certificate/donor awaiting its authenticated height config.
#[derive(Clone, Debug)]
struct DeferredSyncDonor {
    qc: Qc,
    responder: PublicKey,
}

/// Sync state (§6.9): one outstanding request, a bounded buffer of verified-shape entries.
#[derive(Clone, Debug, Default)]
pub(super) struct SyncState {
    /// Highest height known (by a verified `CommitQC`) to be committed.
    verified: u64,
    /// Highest height hinted by an unverifiable `CommitQC` from a member of `C_h`.
    hint: u64,
    sources: Vec<PublicKey>,
    rotate: usize,
    /// Re-request this current missing-body height after a deferred donor failed validation.
    refresh_height: Option<u64>,
    /// `(peer, from_height, deadline)` of the outstanding request.
    outstanding: Option<(PublicKey, u64, u64)>,
    /// Unanswered requests `(peer, from_height)`, oldest first (bounded). Each is answered by
    /// at most one response, whenever it arrives, also after the request was retried
    /// elsewhere (§6.9 rule 3).
    asked: Vec<(PublicKey, u64)>,
    /// Sources that answered the hint with nothing, consecutively.
    empty_from: Vec<PublicKey>,
    pub(super) buffer: BTreeMap<u64, BufferedSyncEntry>,
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

/// Buffer charge of an entry: its exact canonical encoding, the native allowances of its inline
/// fields and skipped-leader key records, and the prepaid responder and alternate-donor slot.
// SPEC: §8.4 bounds the buffer by `2·sync_max_bytes`, the canonical bytes a response is served
// under (§6.9 rule 4). An entry is buffered before its certificate and skipped leaders are
// checked, so it is charged at least what it actually holds: its exact canonical encoded
// length plus fixed native allowances, not the table plus a per-header and per-leader
// allowance (Appendix E, E26).
fn entry_bytes(entry: &SyncEntry) -> usize {
    let skipped = entry.manifest.header.skipped_leaders.len();
    #[cfg(not(sumeragi_mutation = "ML35"))]
    let held = norito::codec::Encode::encoded_len(entry)
        .saturating_add(SYNC_ENTRY_NATIVE_ALLOWANCE)
        .saturating_add(skipped.saturating_mul(SYNC_SKIPPED_LEADER_NATIVE_ALLOWANCE));
    // ML35: the former allowance, the table plus 256 + 2048 bytes and 64 per skipped leader.
    #[cfg(sumeragi_mutation = "ML35")]
    let held = entry
        .manifest
        .availability
        .as_slice()
        .len()
        .saturating_add(256 + crate::types::MAX_CONTROL_WITNESS_BYTES)
        .saturating_add(skipped.saturating_mul(64));
    held.saturating_add(SYNC_DONOR_RESERVATION)
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
        if self
            .sync
            .refresh_height
            .is_some_and(|height| height != next)
        {
            self.sync.refresh_height = None;
        }
        if self.sync.outstanding.is_some() || self.sync.target() < next {
            if self.sync.target() < next {
                self.sync.verified = 0;
                self.sync.hint = 0;
            }
            return;
        }
        #[cfg(not(sumeragi_mutation = "ME3"))]
        self.keep_buffer_contiguous(next);
        if self.sync.refresh_height.is_none()
            && self.sync.buffer.len() >= usize::from(self.local.sync_batch)
        {
            return;
        }
        let from_height = self.sync.refresh_height.unwrap_or_else(|| {
            self.sync
                .buffer
                .last_key_value()
                .map_or(next, |(h, _)| h.saturating_add(1))
                .max(next)
        });
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
            let bytes: usize = dropped.values().map(|buffered| buffered.charge).sum();
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
            let height = qc.height;
            if height < self.next_height() {
                continue;
            }
            if let Some(buffered) = self.sync.buffer.get(&height) {
                // Different exact-q signer subsets may certify the same manifest/value.
                // Keep the original carrier; a donor's own alternative must authenticate.
                let same_value = buffered.entry.manifest == entry.manifest
                    && buffered.entry.commit_qc.kind == qc.kind
                    && buffered.entry.commit_qc.instance == qc.instance
                    && buffered.entry.commit_qc.epoch == qc.epoch
                    && buffered.entry.commit_qc.block_hash == qc.block_hash
                    && buffered.entry.commit_qc.result == qc.result;
                if !same_value {
                    continue;
                }
                let known = self.config(height).is_some();
                if known && !self.verify_qc_cached(qc) {
                    continue;
                }
                let deferred = (!known).then(|| DeferredSyncDonor {
                    qc: entry.commit_qc,
                    responder: from.clone(),
                });
                let Some(buffered) = self.sync.buffer.get_mut(&height) else {
                    continue;
                };
                // Initial admission reserves the full alternate and both maximum keys.
                // A legal later certificate/donor never needs additional buffer capacity.
                buffered.deferred = deferred;
                if known {
                    buffered.responder = from.clone();
                    if self.sync.refresh_height == Some(height) {
                        self.sync.refresh_height = None;
                    }
                }
                continue;
            }
            let charge = entry_bytes(&entry);
            if self.sync.buffer.len() >= max_entries
                || self.sync.buffer_bytes.saturating_add(charge) > max_bytes
            {
                break;
            }
            self.sync.buffer_bytes = self.sync.buffer_bytes.saturating_add(charge);
            self.sync.buffer.insert(
                height,
                BufferedSyncEntry {
                    entry,
                    responder: from.clone(),
                    deferred: None,
                    charge,
                },
            );
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
            let bytes: usize = stale.values().map(|buffered| buffered.charge).sum();
            self.sync.buffer_bytes = self.sync.buffer_bytes.saturating_sub(bytes);
            if self.awaiting || self.halted.is_some() || self.height != next {
                return;
            }
            let Some(mut buffered) = self.sync.buffer.remove(&next) else {
                return;
            };
            self.sync.buffer_bytes = self.sync.buffer_bytes.saturating_sub(buffered.charge);
            let entry = &buffered.entry;
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
                if let Some(deferred) = buffered.deferred.take() {
                    if self.verify_qc_cached(&deferred.qc) {
                        buffered.responder = deferred.responder;
                        if self.sync.refresh_height == Some(next) {
                            self.sync.refresh_height = None;
                        }
                    } else if !cfg!(sumeragi_mutation = "ML34") {
                        // The original carrier already verified. Keep acquiring its body,
                        // but a rejected deferred donor must not prevent a fresh answer
                        // merely because this height remains in the contiguous buffer.
                        self.sync.verified = self.sync.verified.max(next);
                        self.sync.refresh_height = Some(next);
                    }
                }
                let responder = buffered.responder.clone();
                self.sync.buffer_bytes = self.sync.buffer_bytes.saturating_add(buffered.charge);
                self.sync.buffer.insert(next, buffered);
                // A restart can retain a want whose original local body is absent and
                // whose peer list is empty. The verified sync source must enrich that
                // same want; keeping only its manifest would leave fetch retries idle.
                if !cfg!(sumeragi_mutation = "ML32") || !self.wants.contains_key(&bh) {
                    self.want(bh, next, self.sync.sources.clone());
                    if !cfg!(sumeragi_mutation = "ML33") {
                        self.want_sync_responder(bh, &responder);
                    }
                }
                self.on_manifest(manifest);
                return;
            }
            self.commit_height(buffered.entry.commit_qc, Via::Sync);
        }
    }

    /// Keep a requested, fully verified current-height sync responder in body retries.
    /// A bounded stale history must not exclude a live donor using a later-generation key.
    fn want_sync_responder(&mut self, bh: Hash32, responder: &PublicKey) {
        if self.is_local_key(responder) {
            return;
        }
        let Some(want) = self.wants.get(&bh) else {
            return;
        };
        // Only process_sync_buffer calls this, after authenticating the current height.
        // This guard keeps its eviction committee and self.n()+8 bound at the same height.
        if want.height != self.height || want.sync_responder.as_ref() == Some(responder) {
            return;
        }
        let height = want.height;
        let Some(config) = self.config(height).cloned() else {
            return;
        };
        let limit = self.n().saturating_add(8);
        let Ok(source) = AvailabilitySource::new(self.instance, height, bh, config.clone()) else {
            return;
        };
        let Some(want) = self.wants.get_mut(&bh) else {
            return;
        };
        if !want.sources.contains(responder) {
            if want.sources.len() >= limit {
                // There are at most n distinct current members in an n+8 list.
                // Preserve them all; no untrusted Status can perform this replacement.
                let Some(victim) = want
                    .sources
                    .iter()
                    .position(|peer| !config.committee.contains(peer))
                else {
                    return;
                };
                want.sources.remove(victim);
            }
            want.sources.push(responder.clone());
        }
        want.sync_responder = Some(responder.clone());
        // This one-shot fetch leaves cursor/attempt/deadline unchanged. Ordinary retries
        // retain the donor too, so driver coalescing cannot restore the stale-only list.
        self.out.push(Action::FetchPayload {
            source,
            peers: vec![responder.clone()],
        });
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
                sync_responder: None,
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
        let mut peers: Vec<PublicKey> = (0..count)
            .filter_map(|i| want.sources.get((cursor + i) % len.max(1)).cloned())
            .collect();
        if let Some(responder) = &want.sync_responder
            && !peers.contains(responder)
            && let Some(last) = peers.last_mut()
        {
            // Keep the original cyclic fanout, including before exponential saturation.
            *last = responder.clone();
        }
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
            .is_some_and(|buffered| &buffered.entry.manifest == manifest)
        {
            let removed = self
                .sync
                .buffer
                .remove(&height)
                .expect("exact rejected entry");
            self.sync.buffer_bytes = self.sync.buffer_bytes.saturating_sub(removed.charge);
            self.keep_buffer_contiguous(self.next_height());
            self.maybe_request_sync();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        availability::{AvailabilityFrame, MAX_AVAILABILITY_FRAME_BYTES, MAX_DA_CHUNK_COUNT},
        message::{BlockHeader, MAX_BITMAP_BYTES},
        types::{
            AggregateSignature, Bitmap, ControlWitness, EpochId, MAX_COMMITTEE_SIZE,
            MAX_CONTROL_WITNESS_BYTES, MAX_PUBLIC_KEY_LEN, SIGNATURE_LEN,
        },
    };

    /// Full donor storage is prepaid, including at the exact logical buffer boundary.
    #[test]
    fn sync_donor_reservation_covers_maximum_entry_and_full_budget_refresh() {
        assert!(
            std::mem::size_of::<Option<DeferredSyncDonor>>() + std::mem::size_of::<PublicKey>()
                <= SYNC_DONOR_RECORD_ALLOWANCE
        );
        let key = PublicKey::new(vec![1; MAX_PUBLIC_KEY_LEN]).unwrap();
        let epoch = EpochId {
            epoch: 1,
            context: Hash32::ZERO,
        };
        let mut frame = vec![0; MAX_AVAILABILITY_FRAME_BYTES];
        frame[..4].copy_from_slice(&MAX_DA_CHUNK_COUNT.to_be_bytes());
        let availability = AvailabilityFrame::from_untrusted(frame).unwrap();
        assert!(availability.has_valid_structure());
        let header = BlockHeader {
            instance: Hash32::ZERO,
            epoch,
            height: 1,
            origin_view: 0,
            parent_hash: Hash32::ZERO,
            parent_result: Hash32::ZERO,
            payload_hash: Hash32::ZERO,
            availability_digest: Hash32::ZERO,
            payload_len: 0,
            proposer: 0,
            skipped_leaders: vec![key.clone(); MAX_COMMITTEE_SIZE],
            control_witness: ControlWitness::try_from_slice(&[0; MAX_CONTROL_WITNESS_BYTES])
                .unwrap(),
        };
        let qc = Qc {
            kind: VoteKind::Commit,
            instance: Hash32::ZERO,
            epoch,
            height: 1,
            view: 0,
            block_hash: Hash32::ZERO,
            result: Hash32::ZERO,
            signers: Bitmap::new(MAX_COMMITTEE_SIZE),
            agg_sig: AggregateSignature([0; SIGNATURE_LEN]),
        };
        assert_eq!(qc.signers.as_bytes().len(), MAX_BITMAP_BYTES);
        let entry = SyncEntry {
            manifest: PayloadManifest {
                header,
                availability,
            },
            commit_qc: qc.clone(),
        };
        let prepaid = entry_bytes(&entry);
        assert_eq!(SYNC_DONOR_RESERVATION, 896);
        // The inline entry (with its full witness capacity) and each key record fit their
        // native allowances; heap bytes are part of the canonical encoding.
        assert!(std::mem::size_of::<SyncEntry>() <= SYNC_ENTRY_NATIVE_ALLOWANCE);
        assert!(std::mem::size_of::<PublicKey>() <= SYNC_SKIPPED_LEADER_NATIVE_ALLOWANCE);
        let encoded = norito::codec::Encode::encoded_len(&entry);
        assert_eq!(
            encoded, 277_269,
            "the generic maximum entry's canonical encoding"
        );
        assert_eq!(
            prepaid,
            encoded
                + SYNC_ENTRY_NATIVE_ALLOWANCE
                + MAX_COMMITTEE_SIZE * SYNC_SKIPPED_LEADER_NATIVE_ALLOWANCE
                + SYNC_DONOR_RESERVATION
        );
        assert_eq!(prepaid, 346_773);
        // The local validator requires `sync_max_bytes ≥ max_block_bytes + FRAME_OVERHEAD`, so
        // the buffer's `2·sync_max_bytes` holds even this maximal entry by itself: the next
        // height is never refused for its size. This is an accounting fixture, not an
        // authenticated certificate/body fixture.
        assert!(prepaid <= 2 * usize::try_from(crate::pacemaker::FRAME_OVERHEAD).unwrap());
        let mut state = SyncState {
            buffer: BTreeMap::from([(
                1,
                BufferedSyncEntry {
                    entry,
                    responder: PublicKey::new(vec![2]).unwrap(),
                    deferred: None,
                    charge: prepaid,
                },
            )]),
            buffer_bytes: prepaid,
            ..SyncState::default()
        };
        let exact_limit = prepaid;
        let buffered = state.buffer.get_mut(&1).unwrap();
        buffered.deferred = Some(DeferredSyncDonor {
            qc: qc.clone(),
            responder: key.clone(),
        });
        buffered.responder = key;
        assert_eq!(entry_bytes(&buffered.entry), exact_limit);
        assert_eq!(buffered.charge, exact_limit);
        buffered.deferred = Some(DeferredSyncDonor {
            qc,
            responder: PublicKey::new(vec![3; MAX_PUBLIC_KEY_LEN]).unwrap(),
        });
        assert_eq!(entry_bytes(&buffered.entry), exact_limit);
        assert_eq!(buffered.charge, exact_limit);
        buffered.deferred = None;
        assert_eq!(buffered.charge, exact_limit);
        assert_eq!(
            state
                .buffer
                .values()
                .map(|buffered| buffered.charge)
                .sum::<usize>(),
            state.buffer_bytes
        );
        let removed = state.buffer.remove(&1).unwrap();
        state.buffer_bytes = state.buffer_bytes.saturating_sub(removed.charge);
        assert!(state.buffer.is_empty());
        assert_eq!(
            state.buffer_bytes, 0,
            "removal refunds the complete original reservation"
        );
    }

    /// ML35 (§8.4, Appendix E E26): a Byzantine responder's well-formed entries, each with the
    /// generic maximum of skipped leaders, keys, witness and table, wait in the buffer with
    /// unverified certificates. Their exact canonical bytes stay within `2·sync_max_bytes`, the
    /// buffer holds exactly their charges, and the response is cut at the first entry whose
    /// charge no longer fits.
    #[test]
    fn det_l35_sync_buffer_charges_canonical_entry_bytes() {
        use crate::{
            api::LocalParams,
            machine::tests::{G_HASH, G_RESULT, H, I, manifest, pick, result_of},
            types::ChainParams,
        };
        use norito::codec::Encode as _;

        let params = ChainParams {
            max_block_bytes: 1024 * 1024,
            ..ChainParams::default()
        };
        let local = LocalParams {
            sync_max_bytes: params.max_block_bytes + crate::pacemaker::FRAME_OVERHEAD,
            ..LocalParams::default()
        };
        let budget = 2 * usize::try_from(local.sync_max_bytes).unwrap();
        let mut h = H::with(4, local, params, pick::set_a(0));
        // Heights 1 and 2 are honest and commit; height 3 then waits for `C_3` (the apply of
        // 1), so the forged entries from 3 on stay buffered with unchecked certificates.
        h.auto_apply = false;
        let mut entries = Vec::new();
        let mut parent = (G_HASH, G_RESULT);
        for height in 1..=2_u64 {
            let block = h.block_at(height, parent, 0, &height.to_be_bytes());
            parent = (h.bh(&block), result_of(&block));
            entries.push(SyncEntry {
                manifest: manifest(&block),
                commit_qc: h.cqc_for(&block, 0),
            });
        }
        let template = h.block_at(3, parent, 0, b"forged");
        let mut frame = vec![0; MAX_AVAILABILITY_FRAME_BYTES];
        frame[..4].copy_from_slice(&MAX_DA_CHUNK_COUNT.to_be_bytes());
        let availability = AvailabilityFrame::from_untrusted(frame).unwrap();
        let key = PublicKey::new(vec![7; MAX_PUBLIC_KEY_LEN]).unwrap();
        for height in 3..=18_u64 {
            let mut header = template.header().clone();
            header.height = height;
            header.skipped_leaders = vec![key.clone(); MAX_COMMITTEE_SIZE];
            header.control_witness =
                ControlWitness::try_from_slice(&[0; MAX_CONTROL_WITNESS_BYTES]).unwrap();
            let manifest = PayloadManifest {
                header,
                availability: availability.clone(),
            };
            let commit_qc = Qc {
                kind: VoteKind::Commit,
                instance: I,
                epoch: manifest.header.epoch,
                height,
                view: 0,
                block_hash: manifest.hash(&h.v.crypto),
                result: Hash32([0x35; 32]),
                signers: Bitmap::new(MAX_COMMITTEE_SIZE),
                agg_sig: AggregateSignature([0; SIGNATURE_LEN]),
            };
            entries.push(SyncEntry {
                manifest,
                commit_qc,
            });
        }
        let source = h.others(1, &[])[0];
        // A member's CommitQC of height 18 is a hint (`C_18` is unknown): a request from 1.
        let hint = entries.last().unwrap().commit_qc.clone();
        let out = h.deliver(source, WireMessage::Qc(hint));
        assert!(out.iter().any(|action| matches!(
            action,
            Action::Send { msg: WireMessage::SyncRequest(request), .. } if request.from_height == 1
        )));
        h.deliver(
            source,
            WireMessage::SyncResponse(SyncResponse {
                instance: I,
                blocks: entries.clone(),
            }),
        );
        assert_eq!(h.core.tip.height, 2, "the honest prefix commits");
        let charge = |entry: &SyncEntry| entry_bytes(entry);
        let heights: Vec<u64> = h.core.sync.buffer.keys().copied().collect();
        let forged = heights.len();
        assert!(
            forged >= 1,
            "a maximal entry fits the smallest admissible budget"
        );
        assert_eq!(heights, (3..).take(forged).collect::<Vec<u64>>());
        let canonical: usize = h
            .core
            .sync
            .buffer
            .values()
            .map(|buffered| buffered.entry.encoded_len())
            .sum();
        assert!(
            canonical <= budget,
            "{canonical} canonical bytes buffered above 2·sync_max_bytes = {budget}"
        );
        assert_eq!(
            h.core.sync.buffer_bytes,
            h.core
                .sync
                .buffer
                .values()
                .map(|buffered| charge(&buffered.entry))
                .sum::<usize>(),
            "the buffer holds exactly the charges of its entries"
        );
        // Admission stopped at the first forged entry that did not fit beside the prefix.
        let admitted: usize = entries[..2 + forged].iter().map(charge).sum();
        assert!(admitted <= budget);
        assert!(admitted + charge(&entries[2 + forged]) > budget);
    }
}
