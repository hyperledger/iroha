//! Audit lines of the driver (`specs/sumeragi.md` §13.5 soak): one line per durable safety
//! record and one per applied block, from which the multi-process soak
//! (`scripts/sumeragi_soak.py`) computes its oracles.
//!
//! - `sumeragi block applied` (INFO), logged by the executor worker once `commit` made the block
//!   the applied state, for every instance (global and lanes): O-AGR, O-LIVE and O-PERF.
//! - `sumeragi record durable` (DEBUG), logged by the persistence worker once the record is
//!   durable, before any effect it covers leaves the node (§7.4, §12.3 O2): O-SIGN. Enable it
//!   with the log filter `iroha_core::sumeragi::driver::audit=debug`.
//!
//! The fields are stable; hashes and keys are lowercase hex. `signed` lists what the record
//! says its key signed at `height` (`-` when nothing), comma-separated:
//!
//! - `proposal:<view>:<block>`: the last proposal;
//! - `prepare:<view>:<block>:<result>`: the last Prepare vote;
//! - `lock:<view>:<block>:<result>`: the lock, which also records every Commit
//!   vote (a Commit at `(h, v)` is always for the lock of view `v`, §6.5);
//! - `timeout:<view>:<view of the carried PrepareQC, or ->`: the last timeout.
//!
//! A record replaced before it was written is never logged, but every signature that leaves the
//! node is covered by a logged record of the same or a later state of its key (§7.4 O-PBS).

use core::fmt;

use iroha_sumeragi::{availability::AvailableBody, message::Qc, safety::SafetyRecord};

/// Log that `record` is durable. Called by the persistence worker right after the write.
pub(super) fn record_durable(record: &SafetyRecord) {
    iroha_logger::debug!(
        instance = %record.instance,
        key = %Hex(record.key.as_bytes()),
        height = record.height,
        epoch = record.epoch.epoch,
        signed = %Signed(record),
        "sumeragi record durable"
    );
}

/// Log that `block`, certified by `commit_qc`, is the applied state. Called by the executor
/// worker right after a successful `commit`.
pub(super) fn block_applied(block: &AvailableBody, commit_qc: &Qc) {
    iroha_logger::info!(
        process_id = std::process::id(),
        instance = %commit_qc.instance,
        height = commit_qc.height,
        view = commit_qc.view,
        origin_view = block.header().origin_view,
        block = %commit_qc.block_hash,
        result = %commit_qc.result,
        proposer = block.header().proposer,
        payload_bytes = block.header().payload_len,
        "sumeragi block applied"
    );
}

/// Lowercase hex of raw bytes.
pub(super) struct Hex<'a>(pub(super) &'a [u8]);

impl fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

/// The `signed` field of a durable record (grammar in the module documentation).
struct Signed<'a>(&'a SafetyRecord);

impl fmt::Display for Signed<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let record = self.0;
        let mut entries: Vec<String> = Vec::with_capacity(4);
        if let Some(proposal) = &record.proposal {
            entries.push(format!(
                "proposal:{}:{}",
                proposal.view, proposal.block_hash
            ));
        }
        if let Some(vote) = &record.prepare {
            entries.push(format!(
                "prepare:{}:{}:{}",
                vote.view, vote.block_hash, vote.result
            ));
        }
        if let Some(lock) = &record.lock {
            entries.push(format!(
                "lock:{}:{}:{}",
                lock.view, lock.block_hash, lock.result
            ));
        }
        if let Some(timeout) = &record.timeout {
            let carried = timeout
                .hq()
                .map_or_else(|| "-".to_owned(), |view| view.to_string());
            entries.push(format!("timeout:{}:{carried}", timeout.view));
        }
        if entries.is_empty() {
            f.write_str("-")
        } else {
            f.write_str(&entries.join(","))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex, PoisonError};

    use iroha_sumeragi::{
        message::VoteKind,
        safety::{RecordedProposal, RecordedTimeout, RecordedVote},
        testing::{FakeCrypto, TEST_EPOCH},
        types::{ChainParams, Committee, Hash32, HeightConfig, PublicKey},
    };
    use tracing::{
        Event, Metadata, Subscriber,
        field::{Field, Visit},
        span,
        subscriber::Interest,
    };

    use super::{
        super::{
            exec::{Commit, ExecDone, ExecOp},
            persist::{Write, perform},
            run_exec,
            tests::{
                block, commit_qc,
                fakes::{FakeBlocks, FakeBodies, FakeExecutor, FakeRecords},
            },
        },
        *,
    };

    /// One captured event: its level, message and the other fields, rendered.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Line {
        level: String,
        message: String,
        fields: Vec<(String, String)>,
    }

    impl Line {
        fn field(&self, name: &str) -> Option<&str> {
            self.fields
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.as_str())
        }
    }

    /// A subscriber that keeps every event of the thread it is the default of.
    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<Line>>>);

    impl Capture {
        /// Run `f` with this subscriber and return the audit lines it logged.
        fn lines(f: impl FnOnce()) -> Vec<Line> {
            let capture = Self::default();
            tracing::subscriber::with_default(capture.clone(), f);
            let lines = capture.0.lock().unwrap_or_else(PoisonError::into_inner);
            lines
                .iter()
                .filter(|line| {
                    line.message == "sumeragi record durable"
                        || line.message == "sumeragi block applied"
                })
                .cloned()
                .collect()
        }
    }

    #[derive(Default)]
    struct Fields {
        message: String,
        fields: Vec<(String, String)>,
    }

    impl Visit for Fields {
        fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
            let rendered = format!("{value:?}");
            if field.name() == "message" {
                self.message = rendered;
            } else {
                self.fields.push((field.name().to_owned(), rendered));
            }
        }
    }

    impl Subscriber for Capture {
        fn register_callsite(&self, _: &'static Metadata<'static>) -> Interest {
            Interest::sometimes()
        }
        fn enabled(&self, _: &Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
            span::Id::from_u64(1)
        }
        fn record(&self, _: &span::Id, _: &span::Record<'_>) {}
        fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}
        fn event(&self, event: &Event<'_>) {
            let mut fields = Fields::default();
            event.record(&mut fields);
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(Line {
                    level: event.metadata().level().to_string(),
                    message: fields.message,
                    fields: fields.fields,
                });
        }
        fn enter(&self, _: &span::Id) {}
        fn exit(&self, _: &span::Id) {}
    }

    const INSTANCE: Hash32 = Hash32([0x11; 32]);

    fn key() -> PublicKey {
        PublicKey::new(vec![0xab, 0xcd, 0x01]).unwrap()
    }

    fn prepare_qc(view: u64, block_hash: Hash32, result: Hash32) -> Qc {
        let mut qc = commit_qc(&block(7, Hash32([1; 32]), Hash32([2; 32]), vec![1]), result);
        qc.kind = VoteKind::Prepare;
        qc.instance = INSTANCE;
        qc.height = 7;
        qc.view = view;
        qc.block_hash = block_hash;
        qc
    }

    /// A record of height 7 that signed a proposal, a Prepare, a timeout and a Commit.
    fn signed_record() -> SafetyRecord {
        let mut record = SafetyRecord::fresh(INSTANCE, TEST_EPOCH.id, key(), 7, None);
        record.proposal = Some(RecordedProposal {
            view: 1,
            block_hash: Hash32([0xb1; 32]),
            justify: None,
        });
        record.prepare = Some(RecordedVote {
            view: 1,
            block_hash: Hash32([0xb1; 32]),
            result: Hash32([0xc1; 32]),
        });
        record.timeout = Some(RecordedTimeout {
            view: 0,
            high_pqc: None,
        });
        record.lock = Some(prepare_qc(1, Hash32([0xb1; 32]), Hash32([0xc1; 32])));
        record
    }

    fn hex32(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    #[test]
    fn signed_lists_every_recorded_signature() {
        let (b1, c1) = (hex32(0xb1), hex32(0xc1));
        assert_eq!(
            Signed(&signed_record()).to_string(),
            format!("proposal:1:{b1},prepare:1:{b1}:{c1},lock:1:{b1}:{c1},timeout:0:-")
        );
        let mut record = signed_record();
        record.timeout = Some(RecordedTimeout {
            view: 2,
            high_pqc: Some(prepare_qc(1, Hash32([0xb1; 32]), Hash32([0xc1; 32]))),
        });
        assert!(Signed(&record).to_string().ends_with(",timeout:2:1"));
    }

    #[test]
    fn signed_of_a_fresh_record_is_a_dash() {
        let record = SafetyRecord::fresh(INSTANCE, TEST_EPOCH.id, key(), 3, None);
        assert_eq!(Signed(&record).to_string(), "-");
    }

    #[test]
    fn record_durable_line_carries_the_record() {
        let record = signed_record();
        let lines = Capture::lines(|| record_durable(&record));
        assert_eq!(lines.len(), 1);
        let line = &lines[0];
        assert_eq!(line.level, "DEBUG");
        assert_eq!(line.message, "sumeragi record durable");
        assert_eq!(line.field("instance"), Some(hex32(0x11).as_str()));
        assert_eq!(line.field("key"), Some("abcd01"));
        assert_eq!(line.field("height"), Some("7"));
        assert_eq!(
            line.field("epoch"),
            Some(TEST_EPOCH.id.epoch.to_string().as_str())
        );
        assert_eq!(
            line.field("signed"),
            Some(Signed(&record).to_string().as_str())
        );
    }

    /// The persistence worker logs a record only once it is durable: a failed write is retried,
    /// not logged; a body is never logged.
    #[test]
    fn a_record_is_logged_only_after_its_write() {
        let crypto = FakeCrypto::new();
        let records = FakeRecords::default();
        let bodies = FakeBodies::default();
        let record = signed_record();
        records.fail_next(1);
        let failed = Capture::lines(|| {
            assert!(
                perform(
                    &records,
                    &bodies,
                    &crypto,
                    Write::Record(Box::new(record.clone()))
                )
                .is_err()
            );
        });
        assert!(failed.is_empty(), "{failed:?}");
        let written = Capture::lines(|| {
            assert!(
                perform(
                    &records,
                    &bodies,
                    &crypto,
                    Write::Record(Box::new(record.clone()))
                )
                .is_ok()
            );
            let body = block(8, Hash32([1; 32]), Hash32([2; 32]), vec![3]);
            assert!(perform(&records, &bodies, &crypto, Write::Body(Box::new(body))).is_ok());
        });
        assert_eq!(written.len(), 1, "{written:?}");
        assert_eq!(written[0].message, "sumeragi record durable");
        assert_eq!(written[0].field("height"), Some("7"));
    }

    /// The executor worker logs a block once `commit` made it the applied state; a refused
    /// commit, which is retried, is not logged.
    #[test]
    fn a_block_is_logged_only_after_its_commit() {
        let config = HeightConfig {
            epoch: Box::new(TEST_EPOCH),
            committee: Committee::new(vec![PublicKey::new(vec![1; 32]).unwrap()]).unwrap(),
            params: ChainParams::default(),
        };
        let mut executor = FakeExecutor::new(Hash32([0xa0; 32]), Hash32([0xa1; 32]), config);
        let blocks = FakeBlocks::default();
        let applied = block(1, Hash32([0xa0; 32]), Hash32([0xa1; 32]), vec![9, 9]);
        let qc = commit_qc(&applied, Hash32([0xe1; 32]));
        let commit = Arc::new(Commit {
            block: applied.clone(),
            qc: qc.clone(),
        });
        executor.state.lock().fail_apply = 1;
        let refused = Capture::lines(|| {
            let done = run_exec(&mut executor, &blocks, ExecOp::Commit(Arc::clone(&commit)));
            assert!(matches!(done, ExecDone::Committed(Err(_))));
        });
        assert!(refused.is_empty(), "{refused:?}");
        let lines = Capture::lines(|| {
            let done = run_exec(&mut executor, &blocks, ExecOp::Commit(Arc::clone(&commit)));
            assert!(matches!(done, ExecDone::Committed(Ok(_))));
        });
        assert_eq!(lines.len(), 1, "{lines:?}");
        let line = &lines[0];
        assert_eq!(line.level, "INFO");
        assert_eq!(line.message, "sumeragi block applied");
        assert_eq!(
            line.field("process_id"),
            Some(std::process::id().to_string().as_str())
        );
        assert_eq!(
            line.field("instance"),
            Some(qc.instance.to_string().as_str())
        );
        assert_eq!(line.field("height"), Some("1"));
        assert_eq!(line.field("view"), Some("0"));
        assert_eq!(line.field("origin_view"), Some("0"));
        assert_eq!(
            line.field("block"),
            Some(qc.block_hash.to_string().as_str())
        );
        assert_eq!(line.field("result"), Some(hex32(0xe1).as_str()));
        assert_eq!(line.field("proposer"), Some("0"));
        assert_eq!(line.field("payload_bytes"), Some("2"));
    }
}
