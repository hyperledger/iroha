//! Simulator cryptography (§13.1): the fake aggregate scheme of [`crate::testing`] wrapped so
//! that every verification is counted (virtual CPU cost per pairing), and signers that record
//! the provenance of every signature in a shared, pruneable log.
//!
//! The log answers two questions:
//! - O-CERT: was `(key, preimage)` genuinely signed by `key`'s signer? The fake scheme is
//!   forgeable by construction (anyone can compute a fake signature), so a certificate that
//!   verifies is additionally checked against the log.
//! - O-SIGN: an honest key never signs two different preimages of one kind at `(I, h, v)`, never
//!   a Prepare or Commit at a view `≤` a timeout view it signed at `h`, and timeouts only for
//!   increasing views. Signatures that never left their node before it crashed are retracted
//!   (O2 guarantees nothing depends on them), so only signatures that may have influenced
//!   others are compared across restarts.

use std::{
    cell::Cell,
    collections::{BTreeMap, BTreeSet},
    hash::{DefaultHasher, Hash, Hasher},
    rc::Rc,
};

use crate::{
    crypto::{Crypto, Signer},
    preimage::{KIND_COMMIT, KIND_ECHO, KIND_PREPARE, KIND_PROPOSAL, KIND_TIMEOUT, TAG_SIG},
    testing::{FakeCrypto, fake_sig},
    types::{AggregateSignature, Hash32, PublicKey, Signature},
};

/// Fingerprint of `(key, preimage)` (deterministic `SipHash` with fixed keys).
pub fn fingerprint(key: &PublicKey, preimage: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    key.as_bytes().hash(&mut hasher);
    preimage.hash(&mut hasher);
    hasher.finish()
}

/// The round coordinates of a consensus signing preimage (§3.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SigSlot {
    /// Kind byte (`KIND_*`).
    pub kind: u8,
    /// Instance id.
    pub instance: Hash32,
    /// Scheduling epoch and complete context signed at this height.
    pub epoch: crate::types::EpochId,
    /// Height.
    pub height: u64,
    /// View.
    pub view: u64,
}

/// Parse `TAG_SIG ‖ kind ‖ I ‖ be64(h) ‖ be64(v) ‖ …`.
pub fn parse_preimage(preimage: &[u8]) -> Option<SigSlot> {
    let rest = preimage.strip_prefix(TAG_SIG)?;
    let (&kind, rest) = rest.split_first()?;
    let instance: [u8; 32] = rest.get(..32)?.try_into().ok()?;
    let epoch = crate::types::EpochId {
        epoch: u64::from_be_bytes(rest.get(32..40)?.try_into().ok()?),
        context: Hash32(rest.get(40..72)?.try_into().ok()?),
    };
    let height = u64::from_be_bytes(rest.get(72..80)?.try_into().ok()?);
    let view = u64::from_be_bytes(rest.get(80..88)?.try_into().ok()?);
    Some(SigSlot {
        kind,
        instance: Hash32(instance),
        epoch,
        height,
        view,
    })
}

/// One logged signature.
#[derive(Clone, Debug)]
struct Entry {
    /// Honest signer's machine (`None` for Byzantine and harness keys).
    machine: Option<usize>,
    exposed: bool,
    height: u64,
    key: PublicKey,
    slot: Option<SigSlot>,
}

/// An honest signature indexed for O-SIGN.
#[derive(Clone, Copy, Debug)]
struct Honest {
    kind: u8,
    view: u64,
    fp: u64,
}

/// `hq` of a timeout preimage (`TAG_SIG ‖ 0x04 ‖ I ‖ h ‖ v ‖ enc(hq)`).
fn timeout_hq(preimage: &[u8]) -> Option<u64> {
    let rest = preimage.get(TAG_SIG.len() + 1 + 32 + 40 + 16..)?;
    match rest.split_first()? {
        (1, bytes) => Some(u64::from_be_bytes(bytes.get(..8)?.try_into().ok()?)),
        _ => None,
    }
}

/// Shared provenance log of every genuine signature in a world.
#[derive(Debug, Default)]
pub struct SigLog {
    entries: BTreeMap<u64, Entry>,
    honest: BTreeMap<(PublicKey, Hash32, u64), Vec<Honest>>,
    violations: Vec<String>,
    /// Honest Commit signatures to check against their `PrepareQC` (drained by the world,
    /// which knows the committees): `(machine, preimage)`.
    pub commits: Vec<(usize, Vec<u8>)>,
    /// Every proposed `(I, h, v, block hash)` (any signer).
    proposed: BTreeSet<(Hash32, u64, u64, Hash32)>,
    /// Keys that must abstain: `(key, I)` → first height at which they may sign (R2, R6).
    abstain: BTreeMap<(PublicKey, Hash32), u64>,
    /// Signatures produced (statistics).
    pub produced: u64,
}

impl SigLog {
    /// Record a signature of `key` over `preimage`; for honest keys run the O-SIGN checks.
    fn record(&mut self, key: &PublicKey, machine: Option<usize>, preimage: &[u8]) {
        self.produced += 1;
        let slot = parse_preimage(preimage);
        // Probe echoes (§3.3) carry no sign-once obligation and are never recorded: they are
        // excluded from O-SIGN and O-PBS (their "height/view" fields are a nonce and a height).
        if slot.is_some_and(|s| s.kind == KIND_ECHO) {
            return;
        }
        let fp = fingerprint(key, preimage);
        let height = slot.map_or(0, |s| s.height);
        let entry = self.entries.entry(fp).or_insert_with(|| Entry {
            machine,
            exposed: false,
            height,
            key: key.clone(),
            slot,
        });
        if machine.is_none() {
            entry.machine = None;
        }
        let block_hash = preimage
            .get(TAG_SIG.len() + 1 + 32 + 40 + 16..TAG_SIG.len() + 1 + 32 + 40 + 16 + 32)
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .map(Hash32);
        if let (Some(slot), Some(bh)) = (slot, block_hash)
            && slot.kind == KIND_PROPOSAL
        {
            self.proposed
                .insert((slot.instance, slot.height, slot.view, bh));
        }
        let (Some(m), Some(slot)) = (machine, slot) else {
            return;
        };
        if let Some(below) = self.abstain.get(&(key.clone(), slot.instance))
            && slot.height < *below
        {
            self.violations.push(format!(
                "O-SIGN: honest machine {m} signed kind {} at h {} while its key must abstain below {below} (R2/R6)",
                slot.kind, slot.height
            ));
        }
        // SR3: a Prepare is only for the proposal of that very view.
        if slot.kind == KIND_PREPARE
            && let Some(bh) = block_hash
            && !self
                .proposed
                .contains(&(slot.instance, slot.height, slot.view, bh))
        {
            self.violations.push(format!(
                "O-SIGN: honest machine {m} signed a Prepare at h {} v {} for a block not proposed in that view",
                slot.height, slot.view
            ));
        }
        let list = self
            .honest
            .entry((key.clone(), slot.instance, slot.height))
            .or_default();
        if list.iter().any(|h| h.fp == fp) {
            return; // identical preimage re-signed (restart R4): not equivocation
        }
        for old in list.iter() {
            if old.kind == slot.kind && old.view == slot.view {
                self.violations.push(format!(
                    "O-SIGN: honest machine {m} signed two different kind-{} preimages at h {} v {}",
                    slot.kind, slot.height, slot.view
                ));
            }
            let fenced = (slot.kind == KIND_PREPARE || slot.kind == KIND_COMMIT)
                && old.kind == KIND_TIMEOUT
                && old.view >= slot.view;
            if fenced {
                self.violations.push(format!(
                    "O-SIGN: honest machine {m} signed kind {} at h {} v {} after a timeout for view {}",
                    slot.kind, slot.height, slot.view, old.view
                ));
            }
            if slot.kind == KIND_TIMEOUT && old.kind == KIND_TIMEOUT && old.view > slot.view {
                self.violations.push(format!(
                    "O-SIGN: honest machine {m} signed a timeout for view {} after one for view {} at h {}",
                    slot.view, old.view, slot.height
                ));
            }
            // The lock is carried (S4, Lemma 2): after a Commit at view v every timeout at the
            // height for a view w ≥ v carries a PrepareQC of view ≥ v.
            let hq = timeout_hq(preimage);
            if slot.kind == KIND_TIMEOUT
                && old.kind == KIND_COMMIT
                && old.view <= slot.view
                && hq.is_none_or(|hq| hq < old.view)
            {
                self.violations.push(format!(
                    "O-SIGN: honest machine {m} signed a timeout at h {} v {} with hq {hq:?} after a Commit at view {}",
                    slot.height, slot.view, old.view
                ));
            }
        }
        if slot.kind == KIND_COMMIT {
            self.commits.push((m, preimage.to_vec()));
        }
        list.push(Honest {
            kind: slot.kind,
            view: slot.view,
            fp,
        });
    }

    /// Whether `key` genuinely signed `preimage` (and the signature was not retracted).
    pub fn was_signed(&self, key: &PublicKey, preimage: &[u8]) -> bool {
        self.entries.contains_key(&fingerprint(key, preimage))
    }

    /// Mark `(key, preimage)` as having left its node; `true` if this is the first exposure.
    pub fn expose(&mut self, key: &PublicKey, preimage: &[u8]) -> bool {
        match self.entries.get_mut(&fingerprint(key, preimage)) {
            Some(entry) if !entry.exposed => {
                entry.exposed = true;
                true
            }
            _ => false,
        }
    }

    /// A crash of `machine`: retract its honest signatures that never left it and that its
    /// durable records do not cover (`durable(key, slot)`). A durably recorded signature is a
    /// commitment: the restart path (R4) re-signs and re-sends exactly it.
    pub fn retract(&mut self, machine: usize, durable: impl Fn(&PublicKey, &SigSlot) -> bool) {
        let gone: BTreeSet<u64> = self
            .entries
            .iter()
            .filter(|(_, e)| {
                e.machine == Some(machine)
                    && !e.exposed
                    && !e.slot.as_ref().is_some_and(|slot| durable(&e.key, slot))
            })
            .map(|(fp, _)| *fp)
            .collect();
        if gone.is_empty() {
            return;
        }
        self.entries.retain(|fp, _| !gone.contains(fp));
        for list in self.honest.values_mut() {
            list.retain(|h| !gone.contains(&h.fp));
        }
    }

    /// Forget signatures of heights below `height` (no honest node signs or verifies there any
    /// more; keeps memory flat in long runs).
    pub fn prune_below(&mut self, height: u64) {
        self.entries
            .retain(|_, e| e.height >= height || e.height == 0);
        self.honest.retain(|(_, _, h), _| *h >= height);
        self.proposed.retain(|(_, h, _, _)| *h >= height);
    }

    /// The highest height at which the honest `key` signed a consensus message of `instance`
    /// (and the signature was not retracted).
    pub fn max_signed_height(&self, key: &PublicKey, instance: &Hash32) -> Option<u64> {
        self.honest
            .iter()
            .filter(|((k, i, _), list)| k == key && i == instance && !list.is_empty())
            .map(|((_, _, h), _)| *h)
            .max()
    }

    /// The key must not sign below `below` at instance `instance` (R2, R6).
    pub fn set_abstain(&mut self, key: &PublicKey, instance: Hash32, below: u64) {
        let slot = self.abstain.entry((key.clone(), instance)).or_insert(0);
        *slot = (*slot).max(below);
    }

    /// O-SIGN violations found so far (drained).
    pub fn take_violations(&mut self) -> Vec<String> {
        std::mem::take(&mut self.violations)
    }

    /// Number of logged signatures.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing is logged.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Shared handle to a [`SigLog`].
pub type SharedLog = std::sync::Arc<std::sync::Mutex<SigLog>>;

/// A signing key of the simulator (fake scheme) that logs every signature.
#[derive(Clone, Debug)]
pub struct SimSigner {
    key: PublicKey,
    machine: Option<usize>,
    log: SharedLog,
}

impl SimSigner {
    /// A signer for `key`; `machine` is set for honest machines (O-SIGN applies).
    pub fn new(key: PublicKey, machine: Option<usize>, log: SharedLog) -> Self {
        Self { key, machine, log }
    }
}

impl Signer for SimSigner {
    fn public_key(&self) -> &PublicKey {
        &self.key
    }

    fn sign(&self, preimage: &[u8]) -> Signature {
        self.log
            .lock()
            .expect("signing log")
            .record(&self.key, self.machine, preimage);
        fake_sig(&self.key, preimage)
    }
}

/// Aggregate the fake signatures of `parts` (same arithmetic as [`FakeCrypto`]).
pub fn aggregate(sigs: &[Signature]) -> AggregateSignature {
    FakeCrypto::new().aggregate(sigs)
}

/// The fake scheme with a pairing counter (virtual CPU cost, §13.1).
#[derive(Clone, Debug, Default)]
pub struct SimCrypto {
    inner: FakeCrypto,
    pairings: Rc<Cell<u64>>,
}

impl SimCrypto {
    /// A counting fake scheme.
    pub fn new() -> Self {
        Self::default()
    }

    /// Pairings performed so far.
    pub fn pairings(&self) -> u64 {
        self.pairings.get()
    }

    fn charge(&self, pairings: usize) {
        let add = u64::try_from(pairings).unwrap_or(u64::MAX);
        self.pairings.set(self.pairings.get().saturating_add(add));
    }
}

impl Crypto for SimCrypto {
    fn hash_chunks(&self, chunks: &[&[u8]]) -> Hash32 {
        self.inner.hash_chunks(chunks)
    }

    fn verify(&self, pk: &PublicKey, msg: &[u8], sig: &Signature) -> bool {
        self.charge(2);
        self.inner.verify(pk, msg, sig)
    }

    fn aggregate(&self, sigs: &[Signature]) -> AggregateSignature {
        self.inner.aggregate(sigs)
    }

    fn verify_aggregate(&self, pks: &[&PublicKey], msg: &[u8], agg: &AggregateSignature) -> bool {
        self.charge(2);
        self.inner.verify_aggregate(pks, msg, agg)
    }

    fn verify_aggregate_multi(
        &self,
        groups: &[(Vec<&PublicKey>, Vec<u8>)],
        agg: &AggregateSignature,
    ) -> bool {
        self.charge(groups.len().saturating_add(1));
        self.inner.verify_aggregate_multi(groups, agg)
    }
}

/// Kind name for traces and reports.
pub fn kind_name(kind: u8) -> &'static str {
    match kind {
        KIND_PROPOSAL => "proposal",
        KIND_PREPARE => "prepare",
        KIND_COMMIT => "commit",
        KIND_TIMEOUT => "timeout",
        KIND_ECHO => "echo",
        _ => "?",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{message::VoteKind, preimage};

    fn key(b: u8) -> PublicKey {
        PublicKey::new(vec![b; 32]).unwrap()
    }

    #[test]
    fn hashing_chunks_does_not_charge_pairings() {
        let crypto = SimCrypto::new();
        let expected = crypto.hash(b"sumeragi/payloadabc");
        assert_eq!(
            crypto.hash_chunks(&[b"sumeragi/payload", b"", b"abc"]),
            expected
        );
        assert_eq!(crypto.pairings(), 0);
    }

    #[test]
    fn osign_checks_and_retraction() {
        let log: SharedLog = std::sync::Arc::default();
        let i = Hash32([1; 32]);
        let epoch = &crate::testing::TEST_EPOCH.id;
        let vote = |kind, height, view, bh: &Hash32| {
            preimage::vote_preimage(kind, &i, epoch, height, view, bh, &i)
        };
        let tmo = |height, view, hq| preimage::tmo_preimage(&i, epoch, height, view, hq);
        let echo = |nonce, height| preimage::echo_preimage(&i, epoch, nonce, height);
        let x = SimSigner::new(key(1), Some(0), std::sync::Arc::clone(&log));
        let prep = |bh: u8| vote(VoteKind::Prepare, 5, 2, &Hash32([bh; 32]));
        let leader = SimSigner::new(key(9), None, std::sync::Arc::clone(&log));
        for bh in 1..=3u8 {
            leader.sign(&preimage::prop_preimage(
                &i,
                epoch,
                5,
                2,
                &Hash32([bh; 32]),
                &i,
            ));
        }
        x.sign(&prep(1));
        x.sign(&prep(1)); // identical re-sign is fine
        assert!(
            log.lock()
                .expect("signing log")
                .take_violations()
                .is_empty()
        );
        // Unexposed signatures are retracted on crash: a different one after restart is fine.
        log.lock().expect("signing log").retract(0, |_, _| false);
        assert!(
            !log.lock()
                .expect("signing log")
                .was_signed(&key(1), &prep(1))
        );
        x.sign(&prep(2));
        assert!(log.lock().expect("signing log").expose(&key(1), &prep(2)));
        assert!(!log.lock().expect("signing log").expose(&key(1), &prep(2)));
        log.lock().expect("signing log").retract(0, |_, _| false);
        assert!(
            log.lock()
                .expect("signing log")
                .was_signed(&key(1), &prep(2))
        );
        x.sign(&prep(3));
        assert_eq!(
            log.lock().expect("signing log").take_violations().len(),
            1,
            "equivocation"
        );
        // Timeout fence.
        x.sign(&tmo(6, 3, None));
        x.sign(&vote(VoteKind::Commit, 6, 3, &i));
        assert_eq!(
            log.lock().expect("signing log").take_violations().len(),
            1,
            "fence"
        );
        // A timeout for an earlier view: out of order (the Lemma 2 lock clause covers only
        // timeouts at views ≥ the Commit's).
        x.sign(&tmo(6, 2, None));
        assert_eq!(
            log.lock().expect("signing log").take_violations().len(),
            1,
            "timeout order"
        );
        // After a Commit at view 1, a later timeout must carry hq ≥ 1.
        x.sign(&vote(VoteKind::Commit, 7, 1, &i));
        x.sign(&tmo(7, 1, Some(1)));
        assert!(
            log.lock()
                .expect("signing log")
                .take_violations()
                .is_empty()
        );
        x.sign(&tmo(7, 2, Some(0)));
        assert_eq!(
            log.lock().expect("signing log").take_violations().len(),
            1,
            "stale lock"
        );
        // Echoes are never recorded or checked.
        x.sign(&echo(7, 7));
        x.sign(&echo(8, 7));
        assert!(
            log.lock()
                .expect("signing log")
                .take_violations()
                .is_empty()
        );
        assert!(
            !log.lock()
                .expect("signing log")
                .was_signed(&key(1), &echo(7, 7))
        );
        assert_eq!(
            log.lock()
                .expect("signing log")
                .max_signed_height(&key(1), &i),
            Some(7)
        );
        assert_eq!(log.lock().expect("signing log").commits.len(), 2);
        // Byzantine keys are logged but not checked.
        let b = SimSigner::new(key(2), None, std::sync::Arc::clone(&log));
        b.sign(&prep(1));
        b.sign(&prep(2));
        assert!(
            log.lock()
                .expect("signing log")
                .take_violations()
                .is_empty()
        );
        // A Prepare for a block never proposed in that view (SR3).
        x.sign(&vote(VoteKind::Prepare, 8, 0, &i));
        assert_eq!(
            log.lock().expect("signing log").take_violations().len(),
            1,
            "unproposed"
        );
        // Abstention (R2/R6).
        log.lock().expect("signing log").set_abstain(&key(1), i, 10);
        x.sign(&tmo(9, 0, None));
        assert_eq!(
            log.lock().expect("signing log").take_violations().len(),
            1,
            "abstain"
        );
        assert!(
            log.lock()
                .expect("signing log")
                .was_signed(&key(2), &prep(1))
        );
        log.lock().expect("signing log").prune_below(6);
        assert!(
            !log.lock()
                .expect("signing log")
                .was_signed(&key(2), &prep(1))
        );
        assert!(!log.lock().expect("signing log").is_empty());
        assert_eq!(parse_preimage(b"junk"), None);
        assert_eq!(kind_name(KIND_TIMEOUT), "timeout");
    }

    #[test]
    fn counting_crypto() {
        let c = SimCrypto::new();
        let k = key(3);
        let sig = fake_sig(&k, b"m");
        assert!(c.verify(&k, b"m", &sig));
        assert_eq!(c.pairings(), 2);
        let agg = c.aggregate(&[sig]);
        assert!(c.verify_aggregate(&[&k], b"m", &agg));
        assert!(c.verify_aggregate_multi(&[(vec![&k], b"m".to_vec())], &agg));
        assert_eq!(c.pairings(), 6);
        assert_eq!(aggregate(&[sig]), agg);
    }
}
