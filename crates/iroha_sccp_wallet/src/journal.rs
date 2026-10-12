//! Resumable SCCP wallet journal keyed by Taira `NetworkId` (spec §7).
//!
//! Every flow journals its raw evidence and state transitions before it submits anything, so a
//! crashed flow resumes where it stopped and never blindly resubmits. The journal reuses
//! `iroha_operation_journal::Journal` for every step: one owner-private directory whose
//! records are written once, atomically (temporary file, `fsync`, hard link) and owner-only,
//! under an exclusive lock.
//!
//! Layout below the configured `journal_dir` (every directory mode `0700`, every file `0600`,
//! no symlinks):
//!
//! ```text
//! <journal_dir>/<network-id-hex>/<kind>-<flow-id-hex>/step-000000/operation.json
//!                                                                /submission.json
//!                                                                /applied.json
//!                                                    /step-000001/…
//! ```
//!
//! - The network directory is the lowercase hex of the Taira `NetworkId`, so records of a reset
//!   Taira (a new `NetworkId`, §4.18) never mix with the old ones.
//! - A flow is identified by its kind and a 32-byte id (the message id of a transfer, or a
//!   caller-chosen digest for committee sync and control relays).
//! - Steps are dense and append-only. `operation.json` is the [`SccpJournalRecordV1`]: the exact
//!   bytes about to be submitted and the raw evidence they were built from. `submission.json`
//!   is the pre-dispatch marker ([`SccpJournalStep::begin_submission`] returns `true` to exactly
//!   one caller). `applied.json` is the [`SccpJournalOutcomeV1`].
//! - Every record repeats the network id, the flow and the step index, and reading checks them
//!   against the directory it came from.
//!
//! A step that is prepared or submitted but has no outcome is the resume point
//! ([`SccpFlowJournal::resume_point`]): a submitted step is reconciled against the chain, never
//! resubmitted.
//!
//! Appending a step creates its directory (and lock) before it installs `operation.json`, so a
//! crash or I/O error in between leaves an empty step ([`SccpStepStateV1::Empty`]). Nothing was
//! dispatched from it, so it is also a resume point: appending the same index again reclaims the
//! directory. It is reopened under its lock when the lock exists; otherwise the directory is
//! removed and created afresh, and `rmdir` refuses to delete anything it holds.
//!
//! TODO(ws51): add the typed per-flow state machines of §7.1–§7.3 on top of these records.

use core::fmt;
use std::{
    fs::{self, File},
    io::Read as _,
    path::{Path, PathBuf},
};

use iroha_data_model::{NetworkId, bridge::SccpNetworkV1};
use iroha_operation_journal::Journal;
use norito::json;

/// Prefix of step directory names.
pub const STEP_DIR_PREFIX: &str = "step-";
/// Most steps of one flow (six decimal digits).
pub const MAX_STEPS: u32 = 999_999;
/// Largest journal record read back (the shared operation journal's own bound).
pub const MAX_RECORD_BYTES: u64 = 4 * 1024 * 1024;

const OPERATION_FILE: &str = "operation.json";
const SUBMISSION_FILE: &str = "submission.json";
const APPLIED_FILE: &str = "applied.json";
/// Lock file `iroha_operation_journal::Journal::create` makes right after the directory.
const LOCK_FILE: &str = "lock";

/// Kind of a resumable flow.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
)]
#[norito(tag = "kind", content = "detail")]
pub enum SccpFlowKindV1 {
    /// Taira → external transfer (§7.1).
    #[norito(rename = "outbound")]
    Outbound,
    /// External → Taira transfer (§7.2).
    #[norito(rename = "inbound")]
    Inbound,
    /// Void and refund of an outbound transfer (§7.3).
    #[norito(rename = "refund")]
    Refund,
    /// Destination native committee synchronization (§7.4).
    #[norito(rename = "committee_sync")]
    CommitteeSync,
    /// Destination control relay (§7.4).
    #[norito(rename = "control_apply")]
    ControlApply,
}

impl SccpFlowKindV1 {
    /// Every kind.
    pub const ALL: [Self; 5] = [
        Self::Outbound,
        Self::Inbound,
        Self::Refund,
        Self::CommitteeSync,
        Self::ControlApply,
    ];

    /// Directory-name label of the kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Outbound => "outbound",
            Self::Inbound => "inbound",
            Self::Refund => "refund",
            Self::CommitteeSync => "committee_sync",
            Self::ControlApply => "control_apply",
        }
    }

    /// The kind of a directory-name label.
    #[must_use]
    pub fn from_label(label: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == label)
    }
}

/// Identity of one flow within a network.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
)]
#[norito(deny_unknown_fields)]
pub struct SccpFlowIdV1 {
    /// Flow kind.
    pub kind: SccpFlowKindV1,
    /// Message id of a transfer, or a caller-chosen digest.
    pub id: [u8; 32],
}

impl SccpFlowIdV1 {
    /// `<kind>-<id-hex>`.
    #[must_use]
    pub fn dir_name(&self) -> String {
        format!("{}-{}", self.kind.as_str(), hex::encode(self.id))
    }

    /// Parse [`Self::dir_name`].
    #[must_use]
    pub fn from_dir_name(name: &str) -> Option<Self> {
        let (label, id) = name.rsplit_once('-')?;
        let kind = SccpFlowKindV1::from_label(label)?;
        if id.len() != 64 || id.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return None;
        }
        let mut bytes = [0_u8; 32];
        hex::decode_to_slice(id, &mut bytes).ok()?;
        Some(Self { kind, id: bytes })
    }
}

/// One piece of raw evidence (a Torii response frame, an RPC result, a receipt).
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
)]
#[norito(no_fast_from_json)]
#[norito(deny_unknown_fields)]
pub struct SccpEvidenceItemV1 {
    /// What the bytes are, e.g. `torii.message_proof` or `evm.roster_state`.
    pub label: String,
    /// The exact bytes as received.
    #[norito(json = "iroha_sccp::api::base64_json")]
    pub bytes: Vec<u8>,
}

/// A prepared step: what is about to be submitted and the evidence it was built from.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
)]
#[norito(no_fast_from_json)]
#[norito(deny_unknown_fields)]
pub struct SccpJournalRecordV1 {
    /// Taira `NetworkId` bytes.
    pub network_id: [u8; 32],
    /// The flow.
    pub flow: SccpFlowIdV1,
    /// Zero-based step index.
    pub step: u32,
    /// Chain the step is submitted to.
    pub chain: SccpNetworkV1,
    /// Stable action label, e.g. `evm.finalize`, `evm.rotate_rosters`, `taira.record`.
    pub action: String,
    /// The exact bytes to submit (a signed transaction), or empty for a read-only step.
    #[norito(json = "iroha_sccp::api::base64_json")]
    pub submission: Vec<u8>,
    /// Raw evidence the submission was built and verified from.
    pub evidence: Vec<SccpEvidenceItemV1>,
}

/// How a step ended.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
)]
#[norito(tag = "outcome", content = "detail")]
pub enum SccpStepOutcomeKindV1 {
    /// Included and successful.
    #[norito(rename = "confirmed")]
    Confirmed,
    /// Included and reverted, or rejected by Taira.
    #[norito(rename = "failed")]
    Failed,
    /// Made unnecessary by state observed later (another party finalized or rotated first).
    #[norito(rename = "superseded")]
    Superseded,
}

/// The final record of a step, written once.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    norito::derive::JsonSerialize,
    norito::derive::JsonDeserialize,
)]
#[norito(no_fast_from_json)]
#[norito(deny_unknown_fields)]
pub struct SccpJournalOutcomeV1 {
    /// How the step ended.
    pub outcome: SccpStepOutcomeKindV1,
    /// Transaction hash or id on the step's chain, or empty.
    #[norito(json = "iroha_sccp::api::base64_json")]
    pub transaction: Vec<u8>,
    /// Raw evidence of the outcome (receipt, status response).
    pub evidence: Vec<SccpEvidenceItemV1>,
}

/// Progress of one step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SccpStepStateV1 {
    /// The directory exists but `operation.json` was never installed (the append stopped
    /// between the two). Nothing was dispatched; append the same index again to reclaim it.
    Empty,
    /// Prepared; nothing was dispatched.
    Prepared,
    /// The pre-dispatch marker exists; reconcile before doing anything else.
    Submitted,
    /// The outcome is recorded.
    Completed(SccpStepOutcomeKindV1),
}

/// A step as found on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SccpStepStatusV1 {
    /// Zero-based step index.
    pub index: u32,
    /// The prepared record; `None` exactly when the state is [`SccpStepStateV1::Empty`].
    pub record: Option<SccpJournalRecordV1>,
    /// Its progress.
    pub state: SccpStepStateV1,
}

/// Journal errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalError {
    /// A file-system operation failed.
    Io {
        /// What was being done.
        context: &'static str,
        /// The I/O error kind.
        kind: std::io::ErrorKind,
    },
    /// A journal path is a symlink, not owner-only, owned by another user, or of the wrong type.
    Unsafe(PathBuf),
    /// A record does not belong where it was found, or steps are not dense.
    Inconsistent(String),
    /// A record is not canonical Norito JSON of its type.
    Malformed(PathBuf),
    /// The underlying shared operation journal refused an operation.
    Storage(String),
    /// Owner-only journals require Unix permissions.
    Unsupported,
}

impl fmt::Display for JournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { context, kind } => write!(formatter, "SCCP journal: {context}: {kind}"),
            Self::Unsafe(path) => write!(
                formatter,
                "SCCP journal path `{}` must be an owner-only, non-symlink entry of the current user",
                path.display()
            ),
            Self::Inconsistent(message) | Self::Storage(message) => {
                write!(formatter, "SCCP journal: {message}")
            }
            Self::Malformed(path) => write!(
                formatter,
                "SCCP journal record `{}` is not a canonical record",
                path.display()
            ),
            Self::Unsupported => {
                formatter.write_str("SCCP journals require Unix owner-only permissions")
            }
        }
    }
}

impl std::error::Error for JournalError {}

fn io(context: &'static str) -> impl FnOnce(std::io::Error) -> JournalError {
    move |error| JournalError::Io {
        context,
        kind: error.kind(),
    }
}

fn storage(error: impl fmt::Display) -> JournalError {
    JournalError::Storage(format!("{error:#}"))
}

#[cfg(unix)]
fn check_private(
    path: &Path,
    metadata: &fs::Metadata,
    directory: bool,
) -> Result<(), JournalError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let kind_ok = if directory {
        metadata.is_dir()
    } else {
        metadata.is_file() && metadata.nlink() == 1
    };
    if metadata.file_type().is_symlink()
        || !kind_ok
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(JournalError::Unsafe(path.to_path_buf()));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private(_: &Path, _: &fs::Metadata, _: bool) -> Result<(), JournalError> {
    Err(JournalError::Unsupported)
}

/// Create `path` as an owner-only directory if missing, then require it to be one.
fn ensure_private_dir(path: &Path) -> Result<(), JournalError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => check_private(path, &metadata, true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            create_private_dir(path)?;
            let metadata = fs::symlink_metadata(path).map_err(io("inspect a directory"))?;
            check_private(path, &metadata, true)
        }
        Err(error) => Err(io("inspect a directory")(error)),
    }
}

#[cfg(unix)]
fn create_private_dir(path: &Path) -> Result<(), JournalError> {
    use std::os::unix::fs::DirBuilderExt as _;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(io("create a directory"))
}

#[cfg(not(unix))]
fn create_private_dir(_: &Path) -> Result<(), JournalError> {
    Err(JournalError::Unsupported)
}

/// Read an owner-only record file; `None` if it does not exist.
fn read_private_file(path: &Path) -> Result<Option<Vec<u8>>, JournalError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io("inspect a record")(error)),
    };
    check_private(path, &metadata, false)?;
    let file = File::open(path).map_err(io("open a record"))?;
    check_private(
        path,
        &file.metadata().map_err(io("inspect a record"))?,
        false,
    )?;
    let mut bytes = Vec::new();
    file.take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(io("read a record"))?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(JournalError::Malformed(path.to_path_buf()));
    }
    Ok(Some(bytes))
}

/// Decode `bytes` as canonical Norito JSON of `T` (re-encoding must reproduce them).
fn decode_canonical<T: json::JsonDeserialize + json::JsonSerialize>(
    path: &Path,
    bytes: &[u8],
) -> Result<T, JournalError> {
    let value: T =
        json::from_slice(bytes).map_err(|_| JournalError::Malformed(path.to_path_buf()))?;
    let canonical =
        json::to_vec(&value).map_err(|_| JournalError::Malformed(path.to_path_buf()))?;
    if canonical != bytes {
        return Err(JournalError::Malformed(path.to_path_buf()));
    }
    Ok(value)
}

/// The journal root (`journal_dir` of the `[sccp]` client config).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SccpJournalRoot {
    root: PathBuf,
}

impl SccpJournalRoot {
    /// Open the root, creating it owner-only if missing (its parent must exist).
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::Unsafe`] for a symlink or a directory with group or other
    /// permissions, or an I/O error.
    pub fn open(root: &Path) -> Result<Self, JournalError> {
        ensure_private_dir(root)?;
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    /// The root directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.root
    }

    /// The journal of one Taira network.
    ///
    /// # Errors
    ///
    /// See [`Self::open`].
    pub fn network(&self, network_id: &NetworkId) -> Result<SccpNetworkJournal, JournalError> {
        let network_id = *network_id.as_bytes();
        let dir = self.root.join(hex::encode(network_id));
        ensure_private_dir(&dir)?;
        Ok(SccpNetworkJournal { dir, network_id })
    }
}

/// The journal of one Taira `NetworkId`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SccpNetworkJournal {
    dir: PathBuf,
    network_id: [u8; 32],
}

impl SccpNetworkJournal {
    /// The Taira `NetworkId` bytes.
    #[must_use]
    pub fn network_id(&self) -> [u8; 32] {
        self.network_id
    }

    /// Open (creating if missing) the journal of `flow`.
    ///
    /// # Errors
    ///
    /// See [`SccpJournalRoot::open`].
    pub fn flow(&self, flow: &SccpFlowIdV1) -> Result<SccpFlowJournal, JournalError> {
        let dir = self.dir.join(flow.dir_name());
        ensure_private_dir(&dir)?;
        Ok(SccpFlowJournal {
            dir,
            network_id: self.network_id,
            flow: *flow,
        })
    }

    /// Every flow journaled for this network, sorted.
    ///
    /// # Errors
    ///
    /// Returns an I/O error or [`JournalError::Inconsistent`] for a foreign entry.
    pub fn flows(&self) -> Result<Vec<SccpFlowIdV1>, JournalError> {
        let mut flows = Vec::new();
        for entry in fs::read_dir(&self.dir).map_err(io("list flows"))? {
            let entry = entry.map_err(io("list flows"))?;
            let name = entry.file_name();
            let flow = name
                .to_str()
                .and_then(SccpFlowIdV1::from_dir_name)
                .ok_or_else(|| {
                    JournalError::Inconsistent(format!(
                        "unexpected entry `{}` in the network journal",
                        name.to_string_lossy()
                    ))
                })?;
            flows.push(flow);
        }
        flows.sort_unstable();
        Ok(flows)
    }
}

/// The journal of one flow: dense, append-only steps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SccpFlowJournal {
    dir: PathBuf,
    network_id: [u8; 32],
    flow: SccpFlowIdV1,
}

impl SccpFlowJournal {
    /// The flow.
    #[must_use]
    pub fn flow(&self) -> SccpFlowIdV1 {
        self.flow
    }

    fn step_dir(&self, index: u32) -> PathBuf {
        self.dir.join(format!("{STEP_DIR_PREFIX}{index:06}"))
    }

    fn check_record(&self, record: &SccpJournalRecordV1, index: u32) -> Result<(), JournalError> {
        if record.network_id != self.network_id || record.flow != self.flow || record.step != index
        {
            return Err(JournalError::Inconsistent(format!(
                "step {index} does not belong to flow {} of this network",
                self.flow.dir_name()
            )));
        }
        Ok(())
    }

    /// Number of steps on disk (steps must be dense from 0).
    ///
    /// # Errors
    ///
    /// Returns an I/O error or [`JournalError::Inconsistent`].
    pub fn step_count(&self) -> Result<u32, JournalError> {
        let mut indexes = Vec::new();
        for entry in fs::read_dir(&self.dir).map_err(io("list steps"))? {
            let entry = entry.map_err(io("list steps"))?;
            let name = entry.file_name();
            let index = name
                .to_str()
                .and_then(|name| name.strip_prefix(STEP_DIR_PREFIX))
                .filter(|digits| digits.len() == 6 && digits.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|digits| digits.parse::<u32>().ok())
                .ok_or_else(|| {
                    JournalError::Inconsistent(format!(
                        "unexpected entry `{}` in the flow journal",
                        name.to_string_lossy()
                    ))
                })?;
            indexes.push(index);
        }
        indexes.sort_unstable();
        for (expected, index) in (0_u32..).zip(&indexes) {
            if *index != expected {
                return Err(JournalError::Inconsistent(format!(
                    "flow {} misses step {expected}",
                    self.flow.dir_name()
                )));
            }
        }
        u32::try_from(indexes.len())
            .map_err(|_| JournalError::Inconsistent("too many steps".to_owned()))
    }

    /// Read one step without taking its lock. A step directory without `operation.json` (and
    /// without later records) is [`SccpStepStateV1::Empty`].
    ///
    /// # Errors
    ///
    /// Returns an I/O, safety, consistency or format error, including for a step that holds a
    /// submission marker or an outcome but no prepared record.
    pub fn status(&self, index: u32) -> Result<SccpStepStatusV1, JournalError> {
        let dir = self.step_dir(index);
        let metadata = fs::symlink_metadata(&dir).map_err(io("inspect a step"))?;
        check_private(&dir, &metadata, true)?;
        // Records are installed in the order operation, submission, outcome and never removed,
        // so reading them in reverse order never sees a later record without its predecessors
        // even while another process advances the step.
        let applied = dir.join(APPLIED_FILE);
        let outcome = read_private_file(&applied)?
            .map(|bytes| decode_canonical::<SccpJournalOutcomeV1>(&applied, &bytes))
            .transpose()?;
        let submitted = read_private_file(&dir.join(SUBMISSION_FILE))?.is_some();
        let operation = dir.join(OPERATION_FILE);
        let Some(bytes) = read_private_file(&operation)? else {
            if outcome.is_some() || submitted {
                return Err(JournalError::Inconsistent(format!(
                    "step {index} has progress records but no prepared record"
                )));
            }
            return Ok(SccpStepStatusV1 {
                index,
                record: None,
                state: SccpStepStateV1::Empty,
            });
        };
        let record: SccpJournalRecordV1 = decode_canonical(&operation, &bytes)?;
        self.check_record(&record, index)?;
        let state = match outcome {
            Some(outcome) => SccpStepStateV1::Completed(outcome.outcome),
            None if submitted => SccpStepStateV1::Submitted,
            None => SccpStepStateV1::Prepared,
        };
        Ok(SccpStepStatusV1 {
            index,
            record: Some(record),
            state,
        })
    }

    /// Every step in order.
    ///
    /// # Errors
    ///
    /// See [`Self::status`].
    pub fn steps(&self) -> Result<Vec<SccpStepStatusV1>, JournalError> {
        (0..self.step_count()?)
            .map(|index| self.status(index))
            .collect()
    }

    /// The step to resume: the last step when it has no outcome yet. An
    /// [`SccpStepStateV1::Empty`] step is resumed by appending its record again.
    ///
    /// # Errors
    ///
    /// See [`Self::status`].
    pub fn resume_point(&self) -> Result<Option<SccpStepStatusV1>, JournalError> {
        let count = self.step_count()?;
        let Some(last) = count.checked_sub(1) else {
            return Ok(None);
        };
        let status = self.status(last)?;
        Ok(match status.state {
            SccpStepStateV1::Completed(_) => None,
            _ => Some(status),
        })
    }

    /// Journal a step and hold its lock. `record.step` must be the next index after a completed
    /// step, or the index of the last step when that step is [`SccpStepStateV1::Empty`] (which
    /// is then reclaimed); the record must name this network and flow.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::Inconsistent`] or a write error.
    pub fn append(&self, record: &SccpJournalRecordV1) -> Result<SccpJournalStep, JournalError> {
        let count = self.step_count()?;
        if let Some(last) = count.checked_sub(1) {
            match self.status(last)?.state {
                SccpStepStateV1::Completed(_) => {}
                SccpStepStateV1::Empty => {
                    if record.step != last {
                        return Err(JournalError::Inconsistent(format!(
                            "step {last} was never prepared; journal it again first"
                        )));
                    }
                    self.check_record(record, last)?;
                    return SccpJournalStep::install(self.reclaim_empty_step(last)?, record);
                }
                SccpStepStateV1::Prepared | SccpStepStateV1::Submitted => {
                    return Err(JournalError::Inconsistent(format!(
                        "step {last} has no outcome yet; resume it first"
                    )));
                }
            }
        }
        if count > MAX_STEPS {
            return Err(JournalError::Inconsistent("too many steps".to_owned()));
        }
        self.check_record(record, count)?;
        SccpJournalStep::install(
            Journal::create(&self.step_dir(count)).map_err(storage)?,
            record,
        )
    }

    /// Lock the [`SccpStepStateV1::Empty`] step `index` for a new prepared record.
    ///
    /// `Journal::create` makes the directory, then its lock, then nothing else until the record
    /// is written. With the lock present the step is reopened under it, which also refuses a
    /// step another process holds. Without it, nothing was ever written: the directory is removed
    /// (`rmdir` fails on anything it holds) and created afresh.
    fn reclaim_empty_step(&self, index: u32) -> Result<Journal, JournalError> {
        let dir = self.step_dir(index);
        match fs::symlink_metadata(dir.join(LOCK_FILE)) {
            Ok(_) => Journal::open(&dir).map_err(storage),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::remove_dir(&dir).map_err(io("remove an unprepared step"))?;
                Journal::create(&dir).map_err(storage)
            }
            Err(error) => Err(io("inspect a step lock")(error)),
        }
    }

    /// Open an existing prepared step and hold its exclusive lock.
    ///
    /// # Errors
    ///
    /// Returns an operation-journal, consistency or format error; an [`SccpStepStateV1::Empty`] step
    /// is refused (append its record again instead).
    pub fn open_step(&self, index: u32) -> Result<SccpJournalStep, JournalError> {
        if self.status(index)?.state == SccpStepStateV1::Empty {
            return Err(JournalError::Inconsistent(format!(
                "step {index} was never prepared; journal it again first"
            )));
        }
        let journal = Journal::open(&self.step_dir(index)).map_err(storage)?;
        let record: SccpJournalRecordV1 = journal.read_operation().map_err(storage)?;
        self.check_record(&record, index)?;
        Ok(SccpJournalStep { journal, record })
    }
}

/// One locked step.
#[derive(Debug)]
pub struct SccpJournalStep {
    journal: Journal,
    record: SccpJournalRecordV1,
}

impl SccpJournalStep {
    /// Install `record` as the prepared record of the locked step `journal`.
    fn install(journal: Journal, record: &SccpJournalRecordV1) -> Result<Self, JournalError> {
        journal.write_operation(record).map_err(storage)?;
        Ok(Self {
            journal,
            record: record.clone(),
        })
    }

    /// The prepared record.
    #[must_use]
    pub fn record(&self) -> &SccpJournalRecordV1 {
        &self.record
    }

    /// Durably record the pre-dispatch marker. Only the call that returns `true` may submit;
    /// `false` means an earlier attempt exists and the step must be reconciled instead.
    ///
    /// # Errors
    ///
    /// Returns an operation-journal error.
    pub fn begin_submission(&self) -> Result<bool, JournalError> {
        self.journal
            .record_submission(&self.record)
            .map_err(storage)
    }

    /// Whether the pre-dispatch marker exists.
    ///
    /// # Errors
    ///
    /// Returns an operation-journal error.
    pub fn submission_recorded(&self) -> Result<bool, JournalError> {
        self.journal
            .submission_recorded(&self.record)
            .map_err(storage)
    }

    /// Record the step's outcome, once (an identical rewrite is accepted).
    ///
    /// # Errors
    ///
    /// Returns an operation-journal error, including for a different outcome.
    pub fn complete(&self, outcome: &SccpJournalOutcomeV1) -> Result<(), JournalError> {
        self.journal
            .write_applied_evidence(outcome)
            .map_err(storage)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    use super::*;

    fn network_id(seed: u8) -> NetworkId {
        NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
            iroha_crypto::Hash::prehashed([seed; 32]),
        ))
    }

    fn flow() -> SccpFlowIdV1 {
        SccpFlowIdV1 {
            kind: SccpFlowKindV1::Outbound,
            id: [0xab; 32],
        }
    }

    fn record(network: &SccpNetworkJournal, step: u32) -> SccpJournalRecordV1 {
        SccpJournalRecordV1 {
            network_id: network.network_id(),
            flow: flow(),
            step,
            chain: SccpNetworkV1::EthereumMainnet,
            action: "evm.finalize".to_owned(),
            submission: vec![0x02, 0xf8, 0x01],
            evidence: vec![SccpEvidenceItemV1 {
                label: "torii.message_proof".to_owned(),
                bytes: vec![1, 2, 3],
            }],
        }
    }

    fn outcome() -> SccpJournalOutcomeV1 {
        SccpJournalOutcomeV1 {
            outcome: SccpStepOutcomeKindV1::Confirmed,
            transaction: vec![0x55; 32],
            evidence: Vec::new(),
        }
    }

    fn root() -> (tempfile::TempDir, SccpJournalRoot) {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = SccpJournalRoot::open(&dir.path().join("journal")).expect("root");
        (dir, root)
    }

    #[test]
    fn flow_ids_roundtrip_through_directory_names() {
        let id = flow();
        let name = id.dir_name();
        assert_eq!(name, format!("outbound-{}", "ab".repeat(32)));
        assert_eq!(SccpFlowIdV1::from_dir_name(&name), Some(id));
        for kind in SccpFlowKindV1::ALL {
            let flow = SccpFlowIdV1 { kind, id: [7; 32] };
            assert_eq!(SccpFlowIdV1::from_dir_name(&flow.dir_name()), Some(flow));
        }
        assert_eq!(SccpFlowIdV1::from_dir_name("outbound-00"), None);
        assert_eq!(
            SccpFlowIdV1::from_dir_name(&format!("mint-{}", "ab".repeat(32))),
            None
        );
        assert_eq!(
            SccpFlowIdV1::from_dir_name(&format!("outbound-{}", "AB".repeat(32))),
            None
        );
    }

    #[test]
    fn committee_flow_label_is_first_release_only() {
        let kind = SccpFlowKindV1::CommitteeSync;
        assert_eq!(kind.as_str(), "committee_sync");
        assert_eq!(SccpFlowKindV1::from_label("committee_sync"), Some(kind));
        assert_eq!(SccpFlowKindV1::from_label("roster_sync"), None);
        let flow = SccpFlowIdV1 { kind, id: [7; 32] };
        assert_eq!(SccpFlowIdV1::from_dir_name(&flow.dir_name()), Some(flow));
        assert_eq!(
            SccpFlowIdV1::from_dir_name(&format!("roster_sync-{}", "07".repeat(32))),
            None
        );
    }

    #[test]
    fn committee_flow_json_rejects_retired_label() {
        let kind = SccpFlowKindV1::CommitteeSync;
        let encoded = String::from_utf8(json::to_vec(&kind).expect("committee flow JSON"))
            .expect("UTF-8 JSON");
        assert!(encoded.contains("committee_sync"), "{encoded}");
        assert_eq!(
            json::from_str::<SccpFlowKindV1>(&encoded).expect("current label decodes"),
            kind
        );
        let retired = encoded.replace("committee_sync", "roster_sync");
        assert!(json::from_str::<SccpFlowKindV1>(&retired).is_err());
    }

    #[test]
    fn records_roundtrip_as_canonical_json() {
        let (_dir, root) = root();
        let network = root.network(&network_id(0x11)).expect("network");
        let record = record(&network, 0);
        let bytes = json::to_vec(&record).expect("json");
        let path = Path::new("operation.json");
        assert_eq!(
            decode_canonical::<SccpJournalRecordV1>(path, &bytes).expect("decodes"),
            record
        );
        let mut spaced = b" ".to_vec();
        spaced.extend_from_slice(&bytes);
        assert_eq!(
            decode_canonical::<SccpJournalRecordV1>(path, &spaced),
            Err(JournalError::Malformed(path.to_path_buf()))
        );
        let text = String::from_utf8(bytes).expect("utf8");
        assert!(text.contains("\"submission\":\"AvgB\""), "{text}");
    }

    #[test]
    fn steps_are_dense_resumable_and_written_once() {
        let (_dir, root) = root();
        let network = root.network(&network_id(0x11)).expect("network");
        let flow_journal = network.flow(&flow()).expect("flow");
        assert_eq!(flow_journal.flow(), flow());
        assert_eq!(flow_journal.resume_point().expect("empty"), None);

        let step = flow_journal.append(&record(&network, 0)).expect("append");
        assert_eq!(step.record().step, 0);
        assert!(
            flow_journal.append(&record(&network, 1)).is_err(),
            "step 0 is open"
        );
        assert!(!step.submission_recorded().expect("marker"));
        assert!(step.begin_submission().expect("first dispatch"));
        assert!(!step.begin_submission().expect("no second dispatch"));
        drop(step);

        let resume = flow_journal
            .resume_point()
            .expect("resume")
            .expect("pending");
        assert_eq!(resume.state, SccpStepStateV1::Submitted);
        let step = flow_journal.open_step(0).expect("reopen");
        step.complete(&outcome()).expect("outcome");
        step.complete(&outcome()).expect("identical rewrite");
        let mut other = outcome();
        other.outcome = SccpStepOutcomeKindV1::Failed;
        assert!(step.complete(&other).is_err(), "outcomes are written once");
        drop(step);
        assert_eq!(flow_journal.resume_point().expect("done"), None);

        assert!(
            flow_journal.append(&record(&network, 2)).is_err(),
            "indexes are dense"
        );
        let second = flow_journal.append(&record(&network, 1)).expect("step 1");
        drop(second);
        let steps = flow_journal.steps().expect("steps");
        assert_eq!(steps.len(), 2);
        assert_eq!(
            steps[0].state,
            SccpStepStateV1::Completed(SccpStepOutcomeKindV1::Confirmed)
        );
        assert_eq!(steps[1].state, SccpStepStateV1::Prepared);
        assert_eq!(network.flows().expect("flows"), vec![flow()]);
    }

    #[test]
    fn an_unprepared_step_is_reported_and_reclaimed() {
        let (_dir, root) = root();
        let network = root.network(&network_id(0x11)).expect("network");
        let flow_journal = network.flow(&flow()).expect("flow");
        let step_dir = |index: u32| flow_journal.step_dir(index);

        // A crash after `mkdirat`, before the lock: an empty directory.
        create_private_dir(&step_dir(0)).expect("empty step");
        let empty = SccpStepStatusV1 {
            index: 0,
            record: None,
            state: SccpStepStateV1::Empty,
        };
        assert_eq!(flow_journal.step_count().expect("count"), 1);
        assert_eq!(flow_journal.status(0).expect("status"), empty);
        assert_eq!(flow_journal.steps().expect("steps"), vec![empty.clone()]);
        assert_eq!(
            flow_journal.resume_point().expect("resume"),
            Some(empty.clone())
        );
        assert!(matches!(
            flow_journal.open_step(0),
            Err(JournalError::Inconsistent(_))
        ));
        assert!(matches!(
            flow_journal.append(&record(&network, 1)),
            Err(JournalError::Inconsistent(_))
        ));
        let step = flow_journal
            .append(&record(&network, 0))
            .expect("reclaimed");
        assert!(step.begin_submission().expect("first dispatch"));
        step.complete(&outcome()).expect("outcome");
        drop(step);
        assert_eq!(flow_journal.resume_point().expect("done"), None);

        // A crash after the lock, before `operation.json`: reopened under its lock.
        drop(Journal::create(&step_dir(1)).expect("locked step"));
        let pending = flow_journal
            .resume_point()
            .expect("resume")
            .expect("pending");
        assert_eq!((pending.index, pending.state), (1, SccpStepStateV1::Empty));
        let held = Journal::open(&step_dir(1)).expect("another holder");
        assert!(
            matches!(
                flow_journal.append(&record(&network, 1)),
                Err(JournalError::Storage(_))
            ),
            "a step another process holds is not reclaimed"
        );
        drop(held);
        let step = flow_journal
            .append(&record(&network, 1))
            .expect("reclaimed");
        assert_eq!(step.record().step, 1);
        drop(step);
        assert_eq!(
            flow_journal.status(1).expect("status").state,
            SccpStepStateV1::Prepared
        );
        assert_eq!(
            flow_journal.status(1).expect("status").record,
            Some(record(&network, 1))
        );
    }

    #[test]
    fn an_unprepared_step_is_never_emptied_by_force() {
        let (_dir, root) = root();
        let network = root.network(&network_id(0x11)).expect("network");
        let flow_journal = network.flow(&flow()).expect("flow");
        let dir = flow_journal.step_dir(0);
        create_private_dir(&dir).expect("empty step");
        fs::write(dir.join("stray"), b"x").expect("stray");
        assert_eq!(
            flow_journal.status(0).expect("status").state,
            SccpStepStateV1::Empty
        );
        assert!(matches!(
            flow_journal.append(&record(&network, 0)),
            Err(JournalError::Io { .. })
        ));
        assert!(dir.join("stray").exists(), "unknown content is kept");

        // Progress records without a prepared record are not an empty step.
        let marker = flow_journal.step_dir(0).join(SUBMISSION_FILE);
        fs::write(&marker, b"{}").expect("marker");
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).expect("chmod");
        assert!(matches!(
            flow_journal.status(0),
            Err(JournalError::Inconsistent(_))
        ));
        assert!(flow_journal.resume_point().is_err());
    }

    #[test]
    fn records_are_bound_to_their_network_and_flow() {
        let (_dir, root) = root();
        let network = root.network(&network_id(0x11)).expect("network");
        let reset = root.network(&network_id(0x12)).expect("reset network");
        let flow_journal = network.flow(&flow()).expect("flow");
        assert!(matches!(
            flow_journal.append(&record(&reset, 0)),
            Err(JournalError::Inconsistent(_))
        ));
        let mut other_flow = record(&network, 0);
        other_flow.flow.kind = SccpFlowKindV1::Refund;
        assert!(flow_journal.append(&other_flow).is_err());
        assert_ne!(network.network_id(), reset.network_id());
    }

    #[test]
    fn unsafe_directories_are_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let open = dir.path().join("open");
        fs::create_dir(&open).expect("mkdir");
        fs::set_permissions(&open, fs::Permissions::from_mode(0o755)).expect("chmod");
        assert_eq!(
            SccpJournalRoot::open(&open),
            Err(JournalError::Unsafe(open.clone()))
        );
        let link = dir.path().join("link");
        let private = dir.path().join("private");
        fs::create_dir(&private).expect("mkdir");
        fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).expect("chmod");
        symlink(&private, &link).expect("symlink");
        assert_eq!(
            SccpJournalRoot::open(&link),
            Err(JournalError::Unsafe(link.clone()))
        );
        let root = SccpJournalRoot::open(&private).expect("private root");
        assert_eq!(root.path(), private);
        let network = root.network(&network_id(0x11)).expect("network");
        fs::write(private.join(hex::encode([0x11; 32])).join("stray"), b"x").expect("stray");
        assert!(matches!(
            network.flows(),
            Err(JournalError::Inconsistent(_))
        ));
        assert!(JournalError::Unsupported.to_string().contains("Unix"));
    }
}
