//! The persisted safety record (spec §7.4): fields, checksummed encoding, decoding with
//! corruption detection, restart classification R1–R6, the R2 anchoring rule and signing-key
//! selection.
//!
//! One record exists per `(instance, key)`. It is written with every signed message
//! (persist-before-send, O2) and restored on restart, so a key never signs twice at one
//! `(h, v)` and never signs with a lower lock than it already committed to.

use core::fmt;
use std::collections::BTreeMap;

use crate::{
    api::{HaltReason, LocalFault},
    crypto::Crypto,
    message::{self, Qc, TimeoutCert, VoteKind},
    types::{Committee, EpochConfig, EpochId, Hash32, PublicKey, ValidatorIndex},
};

/// Largest accepted record encoding (a record at `n = 1024` stays far below this).
pub const MAX_RECORD_BYTES: usize = 1 << 20;

/// `(view, block_hash, justify)` of the last proposal signed at the record's height.
#[derive(Clone, PartialEq, Eq, Debug, norito::Encode, norito::Decode)]
pub struct RecordedProposal {
    /// View of the proposal.
    pub view: u64,
    /// Proposed block hash.
    pub block_hash: Hash32,
    /// The TC that justified the view (`None` at view 0).
    pub justify: Option<TimeoutCert>,
}

/// `(view, block_hash, result)` of the last Prepare vote signed.
#[derive(Clone, Copy, PartialEq, Eq, Debug, norito::Encode, norito::Decode)]
pub struct RecordedVote {
    /// View of the vote.
    pub view: u64,
    /// Voted block hash.
    pub block_hash: Hash32,
    /// Voted result.
    pub result: Hash32,
}

/// `(view, exact PrepareQC carried)` of the last timeout signed.
#[derive(Clone, PartialEq, Eq, Debug, norito::Encode, norito::Decode)]
pub struct RecordedTimeout {
    /// Timed-out view.
    pub view: u64,
    /// The exact `PrepareQC` the timeout carried.
    pub high_pqc: Option<Qc>,
}

impl RecordedTimeout {
    /// `hq` of the recorded timeout.
    pub fn hq(&self) -> Option<u64> {
        self.high_pqc.as_ref().map(|qc| qc.view)
    }
}

/// The persisted safety record of one key at one height (§7.4).
#[derive(Clone, PartialEq, Eq, Debug, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_sumeragi::SafetyRecord")]
pub struct SafetyRecord {
    /// Instance id.
    pub instance: Hash32,
    /// Exact scheduling context under which every retained signature was produced.
    pub epoch: EpochId,
    /// The consensus key this record belongs to.
    pub key: PublicKey,
    /// Round height the record describes.
    pub height: u64,
    /// `CommitQC` of `height − 1` (`None` at `g + 1`).
    pub parent_commit_qc: Option<Qc>,
    /// Last proposal signed.
    pub proposal: Option<RecordedProposal>,
    /// Last Prepare signed.
    pub prepare: Option<RecordedVote>,
    /// Last timeout signed.
    pub timeout: Option<RecordedTimeout>,
    /// Lock (`high_pqc`) at write time; also the record of every Commit (§6.5: a Commit at
    /// `(h, v)` is always for the lock of view `v`, durable before the vote leaves).
    pub lock: Option<Qc>,
    /// `high_tc` at write time.
    pub high_tc: Option<TimeoutCert>,
}

impl SafetyRecord {
    /// `SafetyRecord::fresh(key, h, parent_commit_qc)` (§6.8): nothing signed yet at `height`.
    pub fn fresh(
        instance: Hash32,
        epoch: EpochId,
        key: PublicKey,
        height: u64,
        parent_commit_qc: Option<Qc>,
    ) -> Self {
        Self {
            instance,
            epoch,
            key,
            height,
            parent_commit_qc,
            proposal: None,
            prepare: None,
            timeout: None,
            lock: None,
            high_tc: None,
        }
    }

    /// Encoding for the durable file: the canonical Norito frame followed by `H(frame)`.
    ///
    /// # Errors
    /// Propagates a Norito serialization failure.
    pub fn encode(&self, crypto: &dyn Crypto) -> Result<Vec<u8>, RecordError> {
        let mut bytes = norito::encode_canonical(self).map_err(|_| RecordError::Encode)?;
        let checksum = crypto.hash(&bytes);
        bytes.extend_from_slice(checksum.as_bytes());
        Ok(bytes)
    }

    /// Decode and check a record read from disk: size, checksum `H(frame)`, canonical Norito
    /// frame, size limits and internal consistency (R1). Never panics.
    ///
    /// # Errors
    /// [`RecordError`] describing the corruption.
    pub fn decode(crypto: &dyn Crypto, bytes: &[u8]) -> Result<Self, RecordError> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(RecordError::TooLarge);
        }
        let split = bytes.len().checked_sub(32).ok_or(RecordError::TooShort)?;
        let (frame, checksum) = bytes.split_at(split);
        if crypto.hash(frame).as_bytes()[..] != checksum[..] {
            return Err(RecordError::Checksum);
        }
        let record: Self = norito::decode_canonical(frame).map_err(|_| RecordError::Decode)?;
        record.check_consistency()?;
        Ok(record)
    }

    /// Internal consistency of a decoded record.
    // SPEC: §7.4 R1 only names checksum/decode failures and instance/key mismatches. A record
    // that decodes but contradicts itself (certificates of other heights, instances or kinds; a
    // timeout carrying a QC above its view; a justify that is not for `view − 1`) was not written
    // by an honest core, so it is treated as corrupt (halt) rather than trusted (Appendix E, E17).
    fn check_consistency(&self) -> Result<(), RecordError> {
        let prepare_qc_here = |qc: &Qc| {
            qc.kind == VoteKind::Prepare
                && qc.height == self.height
                && qc.instance == self.instance
                && qc.epoch == self.epoch
                && message::check_qc(qc).is_ok()
        };
        let tc_here = |tc: &TimeoutCert| {
            tc.height == self.height
                && tc.instance == self.instance
                && tc.epoch == self.epoch
                && message::check_tc(tc).is_ok()
        };
        let valid = self.key.is_well_formed()
            && self.parent_commit_qc.as_ref().is_none_or(|qc| {
                qc.kind == VoteKind::Commit
                    && qc.instance == self.instance
                    && Some(qc.height) == self.height.checked_sub(1)
                    && message::check_qc(qc).is_ok()
            })
            && self.lock.as_ref().is_none_or(prepare_qc_here)
            && self.high_tc.as_ref().is_none_or(tc_here)
            && self.timeout.as_ref().is_none_or(|timeout| {
                timeout
                    .high_pqc
                    .as_ref()
                    .is_none_or(|qc| prepare_qc_here(qc) && qc.view <= timeout.view)
            })
            && self.proposal.as_ref().is_none_or(|proposal| {
                match (&proposal.justify, proposal.view.checked_sub(1)) {
                    (None, None) => true,
                    (Some(tc), Some(prev)) => tc_here(tc) && tc.view == prev,
                    _ => false,
                }
            });
        valid.then_some(()).ok_or(RecordError::Inconsistent)
    }

    /// `timeout_view` restored from the record (R4).
    pub fn timeout_view(&self) -> Option<u64> {
        self.timeout.as_ref().map(|t| t.view)
    }

    /// The view to resume in (R4): the maximum of the `proposal`, `prepare`, `timeout` and
    /// `lock` views and `high_tc.view + 1` over the entries present (0 if none); the views of
    /// `parent_commit_qc` and of certificates nested inside entries are not used.
    pub fn resume_view(&self) -> u64 {
        [
            self.proposal.as_ref().map(|p| p.view),
            self.prepare.map(|v| v.view),
            self.timeout.as_ref().map(|t| t.view),
            self.lock.as_ref().map(|qc| qc.view),
            self.high_tc.as_ref().map(|tc| tc.view.saturating_add(1)),
        ]
        .into_iter()
        .flatten()
        .max()
        .unwrap_or(0)
    }
}

/// Why a record failed to encode or decode (R1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordError {
    /// Norito serialization failed.
    Encode,
    /// Shorter than the 32-byte checksum.
    TooShort,
    /// Larger than [`MAX_RECORD_BYTES`].
    TooLarge,
    /// `H(frame)` does not match.
    Checksum,
    /// The frame is not a canonical Norito encoding of a record.
    Decode,
    /// Decoded, but contradicts itself.
    Inconsistent,
    /// Belongs to another instance.
    WrongInstance,
    /// Belongs to another key.
    WrongKey,
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for RecordError {}

/// What the driver found on disk for one configured or retired key (§7.4 Restart). A record
/// exists only if `PersistSafety` or the installation event wrote it (§7.4 record provenance);
/// every other case is `Absent`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RecordState {
    /// The record file's bytes.
    Present(Vec<u8>),
    /// No record file for this `(instance, key)`.
    Absent,
}

/// R1 for one key: decode and check a `Present` record (checksum, encoding, consistency,
/// instance and key); `Ok(None)` for `Absent`.
///
/// # Errors
/// [`RecordError`] when the record is corrupt or belongs to another instance or key
/// (`Halt(SafetyRecordCorrupt)`).
pub fn read_record(
    crypto: &dyn Crypto,
    instance: &Hash32,
    key: &PublicKey,
    state: &RecordState,
) -> Result<Option<SafetyRecord>, RecordError> {
    let RecordState::Present(bytes) = state else {
        return Ok(None);
    };
    let record = SafetyRecord::decode(crypto, bytes)?;
    if &record.instance != instance {
        return Err(RecordError::WrongInstance);
    }
    if &record.key != key {
        return Err(RecordError::WrongKey);
    }
    Ok(Some(record))
}

/// R5 (§7.4 step 2): the first record (in key order) at height `t + 2`, if any. At most one key
/// has a record at any height; R5 runs at most once.
pub fn recommit_candidate(
    records: &[Option<SafetyRecord>],
    tip_height: u64,
) -> Option<&SafetyRecord> {
    let target = tip_height.checked_add(2)?;
    records
        .iter()
        .flatten()
        .find(|record| record.height == target)
}

/// Classification of one key against the block-store tip `t` after R5 (§7.4 step 3).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RestartPlan {
    /// R2: `Absent` → the key is unanchored until the probe anchors it;
    /// `LocalFault(RecordMissing)`.
    Unanchored,
    /// R3: `record.height ≤ t`: nothing to restore (those heights are committed).
    Past,
    /// R4: `record.height == t + 1`: this record restores the round.
    Resume(Box<SafetyRecord>),
    /// R6: `record.height ≥ t + 2` (the block store lost its tail): the key abstains below
    /// `record.height` and the round is restored from the record there;
    /// `LocalFault(StoreBehindRecord)`.
    Ahead(Box<SafetyRecord>),
}

impl RestartPlan {
    /// Classify one key's (R1-checked) record against the tip height `tip_height`.
    pub fn classify(record: Option<SafetyRecord>, tip_height: u64) -> Self {
        let Some(record) = record else {
            return if cfg!(sumeragi_mutation = "MS31") {
                Self::Past
            } else {
                Self::Unanchored
            };
        };
        match record.height {
            x if x <= tip_height => Self::Past,
            x if x == tip_height.saturating_add(1) => Self::Resume(Box::new(record)),
            #[cfg(not(sumeragi_mutation = "MS32b"))]
            _ => Self::Ahead(Box::new(record)),
            #[cfg(sumeragi_mutation = "MS32b")]
            _ => Self::Past,
        }
    }

    /// The first height at which the key may sign (`0` = no restriction; R2 keys are held back
    /// by being unanchored instead, see [`RestartPlan::unanchored`]).
    pub fn abstain_below(&self) -> u64 {
        match self {
            Self::Ahead(record) => record.height,
            Self::Unanchored | Self::Past | Self::Resume(_) => 0,
        }
    }

    /// Whether the key starts unanchored (R2).
    pub fn unanchored(&self) -> bool {
        matches!(self, Self::Unanchored)
    }

    /// The restored record, if the plan resumes from one (R4, R6).
    pub fn record(&self) -> Option<&SafetyRecord> {
        match self {
            Self::Resume(record) | Self::Ahead(record) => Some(record),
            Self::Unanchored | Self::Past => None,
        }
    }

    /// The local fault to report at startup (R2, R6).
    pub fn local_fault(&self) -> Option<LocalFault> {
        match self {
            Self::Unanchored => Some(LocalFault::RecordMissing),
            Self::Ahead(record) => Some(LocalFault::StoreBehindRecord {
                record_height: record.height,
            }),
            Self::Past | Self::Resume(_) => None,
        }
    }
}

/// R5 check: the record's `parent_commit_qc` must be a valid `CommitQC` of height `t + 1` under
/// `committee = C_{t+1}`. Returns the certificate to commit. That its block extends the tip is
/// checked when the body arrives (§6.9 rule 6).
///
/// # Errors
/// `HaltReason::SafetyRecordInconsistent` when it is missing or does not verify.
pub fn check_recommit<'a>(
    crypto: &dyn Crypto,
    committee_next: &Committee,
    epoch_next: &EpochConfig,
    tip_height: u64,
    record: &'a SafetyRecord,
) -> Result<&'a Qc, HaltReason> {
    let qc = record
        .parent_commit_qc
        .as_ref()
        .ok_or(HaltReason::SafetyRecordInconsistent)?;
    let valid = qc.kind == VoteKind::Commit
        && Some(qc.height) == tip_height.checked_add(1)
        && epoch_next.contains(qc.height)
        && (cfg!(sumeragi_mutation = "MS32a")
            || crate::crypto::Verifier::new(
                crypto,
                &record.instance,
                &epoch_next.id,
                committee_next,
            )
            .verify_qc(qc)
            .is_ok());
    valid
        .then_some(qc)
        .ok_or(HaltReason::SafetyRecordInconsistent)
}

/// The R2 anchoring threshold `2f + 1` for a committee with fault threshold `f` (§1.2, §7.4 R2).
/// This is the only count in the crate other than the quorum `q = n − f`; it is computed from
/// `f`, never through [`crate::types::quorum`].
pub const fn anchor_threshold(f: usize) -> usize {
    2 * f + 1
}

/// R2 anchoring check (§7.4): with `t' = tip_height` and `next = C_{t'+2}`, the unanchored keys
/// become anchored once fresh, verified echoes of `2f + 1` distinct member keys of `next` other
/// than this node's own keys (`own`) each report a height `≤ t' + 1`. `probe` holds the lowest
/// height reported per member key. With `n = 1` no other member exists, so a key never anchors.
pub fn anchored(
    next: &Committee,
    own: impl Fn(&PublicKey) -> bool,
    probe: &BTreeMap<PublicKey, u64>,
    tip_height: u64,
) -> bool {
    let limit = tip_height.saturating_add(1);
    let replies = next
        .members()
        .iter()
        .filter(|key| !own(key))
        .filter(|key| probe.get(*key).is_some_and(|height| *height <= limit))
        .count();
    replies >= anchor_threshold(next.f())
}

/// Which configured key signs at a height (§7.4 Keys).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignerChoice {
    /// No configured key may sign (observer at this height).
    Observer,
    /// The configured key at this index signs; it is `C_h[member]`.
    Key {
        /// Index into the configured keys.
        slot: usize,
        /// Canonical index of the key in `C_h`.
        member: ValidatorIndex,
    },
    /// Two or more configured keys are in `C_h`: none signs (`LocalFault(KeyConflict)`).
    Conflict,
}

/// Select the signing key at `height` among configured `(key, abstain_below, anchored)`
/// triples (retired keys are not passed): the unique configured key in `committee = C_h`, if it
/// is anchored and does not abstain at `height`.
// SPEC: "if two configured keys are in C_h it signs with neither" is applied to every configured
// key in C_h, abstaining, unanchored or not (the safe reading: a conflict never resolves to
// signing) (Appendix E, E18).
pub fn select_signer(
    keys: &[(&PublicKey, u64, bool)],
    committee: &Committee,
    height: u64,
) -> SignerChoice {
    let mut found: Option<(usize, ValidatorIndex, u64, bool)> = None;
    for (slot, (key, abstain_below, anchored)) in keys.iter().enumerate() {
        if let Some(member) = committee.index_of(key) {
            if found.is_some() {
                return SignerChoice::Conflict;
            }
            found = Some((slot, member, *abstain_below, *anchored));
        }
    }
    match found {
        Some((slot, member, abstain_below, true)) if height >= abstain_below => {
            SignerChoice::Key { slot, member }
        }
        _ => SignerChoice::Observer,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        message::TcEntry,
        testing::{FakeCrypto, FakeValidators},
        types::{AggregateSignature, SIGNATURE_LEN},
    };

    const I: Hash32 = Hash32([0x11; 32]);

    fn h(byte: u8) -> Hash32 {
        Hash32([byte; 32])
    }

    fn full_record(v: &FakeValidators, height: u64) -> SafetyRecord {
        let lock = v.qc(VoteKind::Prepare, &I, height, 3, &h(2), &h(3), &[0, 1, 2]);
        let older = v.qc(VoteKind::Prepare, &I, height, 1, &h(4), &h(5), &[0, 1, 2]);
        let tc = v.tc(
            &I,
            height,
            3,
            &[(0, Some(lock.clone())), (1, Some(older.clone())), (2, None)],
        );
        let justify = v.tc(
            &I,
            height,
            2,
            &[(0, Some(older.clone())), (1, None), (3, None)],
        );
        SafetyRecord {
            epoch: crate::testing::TEST_EPOCH.id,
            instance: I,
            key: v.key(1),
            height,
            parent_commit_qc: Some(v.qc(
                VoteKind::Commit,
                &I,
                height - 1,
                0,
                &h(6),
                &h(7),
                &[0, 1, 2],
            )),
            proposal: Some(RecordedProposal {
                view: 3,
                block_hash: h(2),
                justify: Some(justify),
            }),
            prepare: Some(RecordedVote {
                view: 3,
                block_hash: h(2),
                result: h(3),
            }),
            timeout: Some(RecordedTimeout {
                view: 4,
                high_pqc: Some(lock.clone()),
            }),
            lock: Some(lock),
            high_tc: Some(tc),
        }
    }

    #[test]
    fn record_round_trip_and_checksum() {
        let v = FakeValidators::new(4, 1, None);
        for record in [
            full_record(&v, 10),
            SafetyRecord::fresh(I, crate::testing::TEST_EPOCH.id, v.key(0), 1, None),
            SafetyRecord::fresh(I, crate::testing::TEST_EPOCH.id, v.key(0), 7, None),
        ] {
            let bytes = record.encode(&v.crypto).unwrap();
            assert_eq!(SafetyRecord::decode(&v.crypto, &bytes), Ok(record.clone()));
            // Norito round trip of the bare record type as well.
            let frame = norito::encode_canonical(&record).unwrap();
            let back: SafetyRecord = norito::decode_canonical(&frame).unwrap();
            assert_eq!(back, record);
        }
    }

    #[test]
    fn record_corruption_detected() {
        let v = FakeValidators::new(4, 1, None);
        let bytes = full_record(&v, 10).encode(&v.crypto).unwrap();
        // Every single-byte flip is detected.
        for pos in 0..bytes.len() {
            let mut bad = bytes.clone();
            bad[pos] ^= 0x01;
            assert!(SafetyRecord::decode(&v.crypto, &bad).is_err(), "pos {pos}");
        }
        // Truncation at every length is detected.
        for len in 0..bytes.len() {
            assert!(SafetyRecord::decode(&v.crypto, &bytes[..len]).is_err());
        }
        assert_eq!(
            SafetyRecord::decode(&v.crypto, &bytes[..40]),
            Err(RecordError::Checksum)
        );
        assert_eq!(
            SafetyRecord::decode(&v.crypto, &[0; 5]),
            Err(RecordError::TooShort)
        );
        assert_eq!(
            SafetyRecord::decode(&v.crypto, &vec![0; MAX_RECORD_BYTES + 1]),
            Err(RecordError::TooLarge)
        );
        // Garbage with a valid checksum is a decode error, never a panic.
        let mut garbage = vec![0x4e, 0x52, 0x54, 0x30, 1, 2, 3];
        garbage.extend_from_slice(v.crypto.hash(&garbage.clone()).as_bytes());
        assert_eq!(
            SafetyRecord::decode(&v.crypto, &garbage),
            Err(RecordError::Decode)
        );
        // Appended trailing data inside the checksummed frame is non-canonical.
        let record = full_record(&v, 10);
        let mut frame = norito::encode_canonical(&record).unwrap();
        frame.push(0);
        let checksum = v.crypto.hash(&frame);
        frame.extend_from_slice(checksum.as_bytes());
        assert_eq!(
            SafetyRecord::decode(&v.crypto, &frame),
            Err(RecordError::Decode)
        );
        assert_eq!(RecordError::Checksum.to_string(), "Checksum");
    }

    fn reencode_err(
        v: &FakeValidators,
        record: &SafetyRecord,
    ) -> Result<SafetyRecord, RecordError> {
        let bytes = record.encode(&v.crypto).unwrap();
        SafetyRecord::decode(&v.crypto, &bytes)
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn record_inconsistency_detected() {
        let v = FakeValidators::new(4, 1, None);
        let base = full_record(&v, 10);
        let other_height = v.qc(VoteKind::Prepare, &I, 9, 3, &h(2), &h(3), &[0, 1, 2]);
        let commit_here = v.qc(VoteKind::Commit, &I, 10, 3, &h(2), &h(3), &[0, 1, 2]);
        let bad_records = vec![
            SafetyRecord {
                lock: Some(other_height.clone()),
                ..base.clone()
            },
            SafetyRecord {
                lock: Some(commit_here.clone()),
                ..base.clone()
            },
            SafetyRecord {
                lock: Some(Qc {
                    instance: h(0x12),
                    ..base.lock.clone().unwrap()
                }),
                ..base.clone()
            },
            SafetyRecord {
                parent_commit_qc: Some(commit_here.clone()),
                ..base.clone()
            },
            SafetyRecord {
                parent_commit_qc: Some(Qc {
                    kind: VoteKind::Prepare,
                    ..base.parent_commit_qc.clone().unwrap()
                }),
                ..base.clone()
            },
            SafetyRecord {
                high_tc: Some(TimeoutCert {
                    height: 9,
                    ..base.high_tc.clone().unwrap()
                }),
                ..base.clone()
            },
            SafetyRecord {
                timeout: Some(RecordedTimeout {
                    view: 2,
                    high_pqc: base.lock.clone(),
                }),
                ..base.clone()
            },
            SafetyRecord {
                timeout: Some(RecordedTimeout {
                    view: 5,
                    high_pqc: Some(other_height),
                }),
                ..base.clone()
            },
            SafetyRecord {
                proposal: Some(RecordedProposal {
                    view: 0,
                    block_hash: h(2),
                    justify: base.high_tc.clone(),
                }),
                ..base.clone()
            },
            SafetyRecord {
                proposal: Some(RecordedProposal {
                    view: 3,
                    block_hash: h(2),
                    justify: None,
                }),
                ..base.clone()
            },
            SafetyRecord {
                proposal: Some(RecordedProposal {
                    view: 5,
                    block_hash: h(2),
                    justify: base.high_tc.clone(),
                }),
                ..base.clone()
            },
            SafetyRecord {
                lock: Some(Qc {
                    signers: crate::types::Bitmap::from_bytes(vec![0; 1000]),
                    ..base.lock.clone().unwrap()
                }),
                ..base.clone()
            },
            SafetyRecord {
                high_tc: Some(TimeoutCert {
                    entries: vec![
                        TcEntry {
                            signer: 0,
                            hq: None
                        };
                        crate::types::MAX_COMMITTEE_SIZE + 1
                    ],
                    ..base.high_tc.clone().unwrap()
                }),
                ..base.clone()
            },
        ];
        for record in bad_records {
            assert_eq!(
                reencode_err(&v, &record),
                Err(RecordError::Inconsistent),
                "{record:?}"
            );
        }
        // A proposal at view 0 without justify is consistent; so is g + 1 without a parent QC.
        let ok = SafetyRecord {
            proposal: Some(RecordedProposal {
                view: 0,
                block_hash: h(2),
                justify: None,
            }),
            parent_commit_qc: None,
            ..base
        };
        assert!(reencode_err(&v, &ok).is_ok());
    }

    #[test]
    fn record_size_at_n31() {
        let v = FakeValidators::new(31, 1, None);
        let q: Vec<u32> = (0..21).collect();
        let lock = v.qc(VoteKind::Prepare, &I, 10, 3, &h(2), &h(3), &q);
        let entries: Vec<(u32, Option<Qc>)> = (0..31)
            .map(|i| (i, if i % 2 == 0 { Some(lock.clone()) } else { None }))
            .collect();
        let tc = v.tc(&I, 10, 3, &entries);
        let justify = v.tc(&I, 10, 3, &entries);
        let record = SafetyRecord {
            epoch: crate::testing::TEST_EPOCH.id,
            instance: I,
            key: v.key(0),
            height: 10,
            parent_commit_qc: Some(v.qc(VoteKind::Commit, &I, 9, 0, &h(6), &h(7), &q)),
            proposal: Some(RecordedProposal {
                view: 4,
                block_hash: h(2),
                justify: Some(justify),
            }),
            prepare: Some(RecordedVote {
                view: 4,
                block_hash: h(2),
                result: h(3),
            }),
            timeout: Some(RecordedTimeout {
                view: 4,
                high_pqc: Some(lock.clone()),
            }),
            lock: Some(lock),
            high_tc: Some(tc),
        };
        let bytes = record.encode(&v.crypto).unwrap();
        // §7.4 estimates ≈ 3 KB of raw fields; Norito framing adds per-field length prefixes.
        assert!(bytes.len() <= 6 * 1024, "record size {}", bytes.len());
        assert!(SafetyRecord::decode(&v.crypto, &bytes).is_ok());
    }

    #[test]
    fn resume_view_and_timeout_view() {
        let v = FakeValidators::new(4, 1, None);
        let record = full_record(&v, 10);
        // timeout view 4 > high_tc.view + 1 = 4 == 4.
        assert_eq!(record.resume_view(), 4);
        assert_eq!(record.timeout_view(), Some(4));
        assert_eq!(record.timeout.as_ref().unwrap().hq(), Some(3));
        let fresh = SafetyRecord::fresh(I, crate::testing::TEST_EPOCH.id, v.key(0), 10, None);
        assert_eq!(fresh.resume_view(), 0);
        assert_eq!(fresh.timeout_view(), None);
        let tc_only = SafetyRecord {
            high_tc: record.high_tc.clone(),
            ..fresh.clone()
        };
        assert_eq!(tc_only.resume_view(), 4);
        let lock_only = SafetyRecord {
            lock: record.lock.clone(),
            ..fresh.clone()
        };
        assert_eq!(lock_only.resume_view(), 3);
        let prepare_only = SafetyRecord {
            prepare: Some(RecordedVote {
                view: 9,
                block_hash: h(1),
                result: h(1),
            }),
            ..fresh
        };
        assert_eq!(prepare_only.resume_view(), 9);
    }

    fn present(v: &FakeValidators, record: &SafetyRecord) -> RecordState {
        RecordState::Present(record.encode(&v.crypto).unwrap())
    }

    #[test]
    fn restart_cases_r1_to_r6() {
        let v = FakeValidators::new(4, 1, None);
        let key = v.key(1);
        let t = 20u64;
        let read = |state: &RecordState| read_record(&v.crypto, &I, &key, state);
        let classify = |state: &RecordState| RestartPlan::classify(read(state).unwrap(), t);

        // R1: corrupt bytes, other instance, other key.
        let mut bytes = full_record(&v, t + 1).encode(&v.crypto).unwrap();
        bytes[50] ^= 0xff;
        assert_eq!(
            read(&RecordState::Present(bytes)),
            Err(RecordError::Checksum)
        );
        let foreign = SafetyRecord::fresh(
            h(0x12),
            crate::testing::TEST_EPOCH.id,
            key.clone(),
            t + 1,
            None,
        );
        assert_eq!(
            read(&present(&v, &foreign)),
            Err(RecordError::WrongInstance)
        );
        let other_key =
            SafetyRecord::fresh(I, crate::testing::TEST_EPOCH.id, v.key(2), t + 1, None);
        assert_eq!(read(&present(&v, &other_key)), Err(RecordError::WrongKey));

        // R2: absent → unanchored (the probe decides when it may sign again).
        let plan = classify(&RecordState::Absent);
        assert_eq!(plan, RestartPlan::Unanchored);
        assert!(plan.unanchored());
        assert_eq!(plan.abstain_below(), 0);
        assert_eq!(plan.local_fault(), Some(LocalFault::RecordMissing));
        assert_eq!(plan.record(), None);

        // R3: record at or below the tip (the initial record at `g` included).
        for height in [0, 1, t - 1, t] {
            let record =
                SafetyRecord::fresh(I, crate::testing::TEST_EPOCH.id, key.clone(), height, None);
            let plan = classify(&present(&v, &record));
            assert_eq!(plan, RestartPlan::Past, "height {height}");
            assert!(!plan.unanchored());
            assert_eq!(plan.local_fault(), None);
        }

        // R4: resume at t + 1.
        let record = full_record_for(&v, &key, t + 1);
        let plan = classify(&present(&v, &record));
        assert_eq!(plan, RestartPlan::Resume(Box::new(record.clone())));
        assert_eq!(plan.record(), Some(&record));
        assert_eq!(plan.abstain_below(), 0);
        assert_eq!(plan.local_fault(), None);

        // R6: record at t + 2 or beyond (after R5 has run, a t + 2 record is R6 only if R5 did
        // not take it, which cannot happen for the record R5 committed).
        for height in [t + 2, t + 7] {
            let record = full_record_for(&v, &key, height);
            let plan = classify(&present(&v, &record));
            assert_eq!(plan, RestartPlan::Ahead(Box::new(record.clone())));
            assert_eq!(plan.abstain_below(), height);
            assert_eq!(
                plan.local_fault(),
                Some(LocalFault::StoreBehindRecord {
                    record_height: height
                })
            );
        }
    }

    #[test]
    fn r5_candidate_is_the_first_record_at_t_plus_2() {
        let v = FakeValidators::new(4, 1, None);
        let t = 20u64;
        let at = |height: u64, key: u32| {
            Some(SafetyRecord::fresh(
                I,
                crate::testing::TEST_EPOCH.id,
                v.key(key),
                height,
                None,
            ))
        };
        let records = vec![None, at(t + 1, 1), at(t + 2, 2), at(t + 2, 3)];
        let candidate = recommit_candidate(&records, t).unwrap();
        assert_eq!((candidate.height, candidate.key.clone()), (t + 2, v.key(2)));
        assert!(recommit_candidate(&records[..2], t).is_none());
        assert!(recommit_candidate(&[], t).is_none());
        assert!(recommit_candidate(&records, u64::MAX).is_none());
    }

    #[test]
    fn r2_anchoring_threshold_and_check() {
        // 2f + 1 from f, never q: n = 4 → 3, n = 5 → 3 (q = 4), n = 7 → 5, n = 22 → 15.
        for (n, want) in [
            (1usize, 1usize),
            (2, 1),
            (3, 1),
            (4, 3),
            (5, 3),
            (7, 5),
            (22, 15),
        ] {
            let v = FakeValidators::new(n, 1, None);
            assert_eq!(anchor_threshold(v.committee.f()), want, "n={n}");
        }
        let v = FakeValidators::new(4, 1, None);
        let me = v.key(0);
        let own = |k: &PublicKey| *k == me;
        let t = 10u64;
        let mut probe = BTreeMap::new();
        // Replies from two other members are not enough; the own key never counts.
        probe.insert(v.key(0), 0);
        probe.insert(v.key(1), t + 1);
        probe.insert(v.key(2), t);
        assert!(!anchored(&v.committee, own, &probe, t));
        // A reply above t + 1 does not count.
        probe.insert(v.key(3), t + 2);
        assert!(!anchored(&v.committee, own, &probe, t));
        probe.insert(v.key(3), t + 1);
        assert!(anchored(&v.committee, own, &probe, t));
        // Keys outside the committee never count.
        let outsider = FakeValidators::new(1, 99, None).key(0);
        let mut probe = BTreeMap::new();
        probe.insert(outsider, 0);
        probe.insert(v.key(1), 0);
        probe.insert(v.key(2), 0);
        assert!(!anchored(&v.committee, own, &probe, t));
        // n = 1: nobody else exists, so a lost record never anchors.
        let single = FakeValidators::new(1, 1, None);
        let only = single.key(0);
        let mut probe = BTreeMap::new();
        probe.insert(only.clone(), 0);
        assert!(!anchored(&single.committee, |k| *k == only, &probe, t));
        // n = 2, 3 (f = 0): one other reply anchors.
        for n in [2usize, 3] {
            let small = FakeValidators::new(n, 1, None);
            let mine = small.key(0);
            let mut probe = BTreeMap::new();
            probe.insert(small.key(1), t);
            assert!(
                anchored(&small.committee, |k| *k == mine, &probe, t),
                "n={n}"
            );
        }
    }

    fn full_record_for(v: &FakeValidators, key: &PublicKey, height: u64) -> SafetyRecord {
        SafetyRecord {
            key: key.clone(),
            ..full_record(v, height)
        }
    }

    #[test]
    fn r5_recommit_check() {
        let v = FakeValidators::new(4, 1, None);
        let t = 20u64;
        let record = full_record_for(&v, &v.key(1), t + 2);
        let qc = check_recommit(
            &v.crypto,
            &v.committee,
            &crate::testing::TEST_EPOCH,
            t,
            &record,
        )
        .unwrap();
        assert_eq!(qc.height, t + 1);
        assert_eq!(qc.signers.count_ones(), v.committee.q());
        // A genuinely signed parent with every member is not an exact-quorum certificate.
        let superseded = record.parent_commit_qc.as_ref().unwrap();
        let over = SafetyRecord {
            parent_commit_qc: Some(v.qc(
                superseded.kind,
                &superseded.instance,
                superseded.height,
                superseded.view,
                &superseded.block_hash,
                &superseded.result,
                &[0, 1, 2, 3],
            )),
            ..record.clone()
        };
        assert_eq!(
            check_recommit(
                &v.crypto,
                &v.committee,
                &crate::testing::TEST_EPOCH,
                t,
                &over
            ),
            Err(HaltReason::SafetyRecordInconsistent)
        );
        // Missing parent QC.
        let missing = SafetyRecord {
            parent_commit_qc: None,
            ..record.clone()
        };
        assert_eq!(
            check_recommit(
                &v.crypto,
                &v.committee,
                &crate::testing::TEST_EPOCH,
                t,
                &missing
            ),
            Err(HaltReason::SafetyRecordInconsistent)
        );
        // Forged parent QC.
        let forged = SafetyRecord {
            parent_commit_qc: Some(Qc {
                agg_sig: AggregateSignature([0; SIGNATURE_LEN]),
                ..record.parent_commit_qc.clone().unwrap()
            }),
            ..record.clone()
        };
        assert_eq!(
            check_recommit(
                &v.crypto,
                &v.committee,
                &crate::testing::TEST_EPOCH,
                t,
                &forged
            ),
            Err(HaltReason::SafetyRecordInconsistent)
        );
        // Wrong committee.
        let other = FakeValidators::new(4, 9, None);
        assert_eq!(
            check_recommit(
                &other.crypto,
                &other.committee,
                &crate::testing::TEST_EPOCH,
                t,
                &record
            ),
            Err(HaltReason::SafetyRecordInconsistent)
        );
        // Wrong tip height.
        assert_eq!(
            check_recommit(
                &v.crypto,
                &v.committee,
                &crate::testing::TEST_EPOCH,
                t + 1,
                &record
            ),
            Err(HaltReason::SafetyRecordInconsistent)
        );
    }

    #[test]
    fn signer_selection() {
        let v = FakeValidators::new(4, 1, None);
        let outsider = FakeValidators::new(1, 77, None).key(0);
        let member = v.key(2);
        let other_member = v.key(3);
        // Unique member key, anchored, not abstaining.
        assert_eq!(
            select_signer(&[(&outsider, 0, true), (&member, 0, true)], &v.committee, 5),
            SignerChoice::Key { slot: 1, member: 2 }
        );
        // Abstaining below 6.
        assert_eq!(
            select_signer(&[(&member, 6, true)], &v.committee, 5),
            SignerChoice::Observer
        );
        assert_eq!(
            select_signer(&[(&member, 6, true)], &v.committee, 6),
            SignerChoice::Key { slot: 0, member: 2 }
        );
        // Unanchored (R2): never signs.
        assert_eq!(
            select_signer(&[(&member, 0, false)], &v.committee, 100),
            SignerChoice::Observer
        );
        // Not a member.
        assert_eq!(
            select_signer(&[(&outsider, 0, true)], &v.committee, 5),
            SignerChoice::Observer
        );
        assert_eq!(select_signer(&[], &v.committee, 5), SignerChoice::Observer);
        // Two member keys: conflict, even if one abstains or is unanchored.
        assert_eq!(
            select_signer(
                &[(&member, 0, true), (&other_member, 100, false)],
                &v.committee,
                5
            ),
            SignerChoice::Conflict
        );
    }

    #[test]
    fn fake_crypto_is_used_for_checksums() {
        let crypto = FakeCrypto::new();
        let record = SafetyRecord::fresh(
            I,
            crate::testing::TEST_EPOCH.id,
            FakeValidators::new(1, 1, None).key(0),
            3,
            None,
        );
        let bytes = record.encode(&crypto).unwrap();
        let (frame, checksum) = bytes.split_at(bytes.len() - 32);
        assert_eq!(crypto.hash(frame).as_bytes(), checksum);
    }
}
