//! Actual Rust SDK preparation, signing and canonical-frame measurement for E.1.
//!
//! This diagnostic target uses the existing shared recorder only as a dev-dependency.
//! It performs no HTTP request and no ledger admission. It demonstrates the Rust SDK's
//! public-call phases, not every SDK family or device thermal adapter. The original
//! harness binds the run context and retains both successful and failed records.
//! Only static labels and public fixture sizes/counts enter the measurement.

use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use iroha::{
    Error, TransactionSigningError,
    client::{AccountClient, AccountTransactionDraft, Client},
    config::UserConfig,
};
use iroha_config_base::{read::ConfigReader, toml::TomlSource};
use iroha_data_model::{
    prelude::InstructionBox,
    transaction::{FeePaymentIntent, SignedTransaction, TransactionPayload},
};
use iroha_measurement::{
    ByteKind, CollectingSink, DirectoryReport, DirectorySink, Finding, FlowKind,
    HARNESS_OUTPUT_DIR_ENV, MeasurementRecord, RecordSink, RunContext, RunIdentity, RunOutcome,
    Session, TeeSink, WorkerDeclaration, read_harness_context, unclassified_numbers,
};
use iroha_model_base::metadata::Metadata;
use iroha_version::codec::DecodeVersioned as _;

const EMITTER: &str = "rust.iroha.sdk_transaction";
const REPETITIONS: u64 = 128;

// Existing public configuration fixture; the diagnostic never contacts this endpoint.
// This known test key is not a user's runtime signing material and is never recorded.
fn account() -> AccountClient {
    let config = toml::toml! {
        chain = "00000000-0000-0000-0000-000000000000"
        network_id = "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0"
        torii_url = "http://127.0.0.1:8080/"
        [account]
        chain_discriminant = 753
        public_key = "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03"
        private_key = "802620CCF31D85E3B32A4BEA59987CE0C78E3B8E2DB93881468AB2435FE45D5C9DCD53"
        [transaction]
        time_to_live_ms = 5000
        status_timeout_ms = 1000
        nonce = false
    };
    let config = ConfigReader::new()
        .with_toml_source(TomlSource::inline(config))
        .read_and_complete::<UserConfig>()
        .expect("public diagnostic configuration")
        .parse()
        .expect("valid diagnostic authority");
    Client::builder(config)
        .build()
        .expect("valid immutable client")
        .account_client()
        .expect("bound direct account")
}

fn draft() -> AccountTransactionDraft {
    AccountTransactionDraft::new(
        Vec::<InstructionBox>::new(),
        FeePaymentIntent::authority(Vec::new(), None),
        Metadata::default(),
    )
    .with_time_to_live(Duration::from_secs(5))
}

fn harness() -> (RunContext, Option<PathBuf>) {
    match std::env::var_os(HARNESS_OUTPUT_DIR_ENV).map(PathBuf::from) {
        Some(directory) => (
            read_harness_context(&directory).expect("original harness context"),
            Some(directory),
        ),
        None => (RunContext::unbound(), None),
    }
}

struct Delivery {
    memory: CollectingSink,
    files: Option<DirectoryReport>,
}

impl Delivery {
    fn new(directory: Option<&Path>, stem: &'static str) -> (Box<dyn RecordSink>, Self) {
        let memory = CollectingSink::new();
        let sink: Box<dyn RecordSink> = Box::new(memory.clone());
        let (sink, files): (Box<dyn RecordSink>, Option<DirectoryReport>) = match directory {
            Some(directory) => {
                let files = DirectorySink::new(directory.to_path_buf(), stem);
                let report = files.report();
                (Box::new(TeeSink::new(sink, Box::new(files))), Some(report))
            }
            None => (sink, None),
        };
        (sink, Self { memory, files })
    }

    fn only(&self) -> MeasurementRecord {
        let mut records = self.memory.take();
        assert_eq!(records.len(), 1, "each actual flow emits exactly once");
        let record = records.remove(0);
        if let Some(files) = &self.files {
            assert!(files.errors().is_empty() && files.partial().is_empty());
            let paths = files.written();
            assert_eq!(paths.len(), 1);
            let bytes = std::fs::read(&paths[0]).expect("retained Norito record");
            let json = std::fs::read_to_string(paths[0].with_extension("json"))
                .expect("retained JSON view");
            assert_eq!(
                MeasurementRecord::from_norito_bytes(&bytes).unwrap(),
                record
            );
            assert_eq!(MeasurementRecord::from_json_view(&json).unwrap(), record);
        }
        assert!(unclassified_numbers(&record.to_json_value()).is_empty());
        assert_eq!(
            MeasurementRecord::from_json_view(&record.to_json_view()).unwrap(),
            record
        );
        assert_eq!(
            MeasurementRecord::from_norito_bytes(&record.to_norito_bytes().unwrap()).unwrap(),
            record
        );
        record
    }
}

// The recorder has no readable decision API. The operation's exact T or E moves
// out unchanged; recording failure never manufactures an SDK error or success.
fn observe<T, E>(
    context: RunContext,
    workload: &'static str,
    sink: Box<dyn RecordSink>,
    operation: impl FnOnce(&Session) -> Result<T, E>,
) -> Result<T, E> {
    let session = Session::begin(
        RunIdentity::new(context, workload, FlowKind::Sdk, EMITTER),
        "sdk_flow",
        WorkerDeclaration {
            workers: 1,
            provenance: "diagnostic.calling_thread",
        },
        sink,
    );
    // Public-call granularity: this parent includes setup between actual API
    // calls. Nested phases expose preparation, signing and frame work separately.
    let parent = session.enter("sdk_operation");
    let result = operation(&session);
    if result.is_err() {
        session.record_failure("sdk_operation", "sdk_error");
        drop(parent);
    } else {
        parent.complete();
    }
    session.finish();
    result
}

fn successful(record: &MeasurementRecord, bound: bool) {
    assert_eq!(record.identity.flow, FlowKind::Sdk);
    assert_eq!(record.identity.emitter, EMITTER);
    assert_eq!(record.outcome, RunOutcome::Succeeded);
    let findings: Vec<_> = record
        .findings()
        .into_iter()
        .filter(|finding| {
            bound
                || !matches!(
                    finding,
                    Finding::IdentityIncomplete { .. } | Finding::DirtyDigestMismatch
                )
        })
        .collect();
    assert!(findings.is_empty(), "public record findings: {findings:?}");
}

#[test]
fn actual_sdk_prepare_sign_and_canonical_frame_emit_shared_records() {
    let account = account();
    let (context, directory) = harness();
    let (sink, delivery) = Delivery::new(directory.as_deref(), "sdk-transaction-success");
    let result: iroha::Result<()> = observe(
        context,
        "sdk.transaction.prepare_sign_frame",
        sink,
        |session| {
            // This scoped counter covers only exact canonical frame Vecs owned by
            // this diagnostic. It does not claim all allocations inside the SDK.
            let frames = session.allocation_counter("owned_canonical_frames");
            for _ in 0..REPETITIONS {
                let phase = session.enter("prepare_transaction");
                let payload = account.prepare_transaction(draft())?;
                phase.complete();
                let phase = session.enter("sign_transaction");
                let signed = account.sign_transaction(payload)?;
                phase.complete();
                let phase = session.enter("canonical_encode");
                let bytes = signed
                    .encode_wire_v1()
                    .expect("actual signed canonical frame");
                let frame_lifetime = frames.buffer(bytes.capacity() as u64);
                session.record_bytes(
                    ByteKind::Transaction,
                    "signed_transaction_frame",
                    bytes.len() as u64,
                );
                phase.complete();
                let phase = session.enter("canonical_decode_and_verify");
                let decoded = SignedTransaction::decode_all_versioned(&bytes)
                    .expect("actual complete canonical reader");
                decoded
                    .verify_signature()
                    .expect("actual SDK signature verifies");
                assert_eq!(decoded.payload(), signed.payload());
                assert_eq!(decoded.encode_wire_v1().unwrap(), bytes);
                drop((bytes, decoded, signed));
                drop(frame_lifetime);
                phase.complete();
            }
            session.record_work("completed_sdk_transactions", REPETITIONS);
            Ok(())
        },
    );
    result.expect("actual SDK workload");
    let record = delivery.only();
    successful(&record, directory.is_some());
    for label in [
        "prepare_transaction",
        "sign_transaction",
        "canonical_encode",
        "canonical_decode_and_verify",
    ] {
        let node = record
            .phase_tree
            .nodes
            .iter()
            .find(|node| node.label == label)
            .unwrap();
        assert_eq!(node.calls, REPETITIONS);
        assert_eq!(node.completed, REPETITIONS);
        assert_eq!(node.unwound, 0);
    }
    assert!(
        record
            .byte_counters
            .entries
            .iter()
            .any(|entry| entry.label == "signed_transaction_frame"
                && entry.total_bytes > 0
                && entry.count == REPETITIONS)
    );
    let buffers = record
        .allocations
        .sources
        .iter()
        .find(|source| source.label == "owned_canonical_frames")
        .unwrap();
    assert_eq!(buffers.allocations, REPETITIONS);
    assert_eq!(buffers.frees, REPETITIONS);
    assert_eq!(buffers.allocated_bytes, buffers.freed_bytes);
    assert_eq!((buffers.live_bytes, buffers.live_buffers), (0, 0));
}

#[test]
fn observation_keeps_the_exact_sdk_signature_and_payload() {
    let account = account();
    let payload = account.prepare_transaction(draft()).unwrap();
    let expected = account
        .sign_transaction(payload.clone())
        .unwrap()
        .encode_wire_v1()
        .unwrap();
    let (context, directory) = harness();
    let (sink, delivery) = Delivery::new(directory.as_deref(), "sdk-signature-identity");
    let actual = observe(context, "sdk.transaction.same_payload", sink, |session| {
        for _ in 1..REPETITIONS {
            let signed = account.sign_transaction(payload.clone())?;
            assert_eq!(signed.encode_wire_v1().unwrap(), expected);
        }
        let signed = account.sign_transaction(payload)?;
        session.record_work("completed_sdk_signatures", REPETITIONS);
        Ok::<_, Error>(signed)
    })
    .unwrap();
    assert_eq!(actual.encode_wire_v1().unwrap(), expected);
    actual.verify_signature().unwrap();
    successful(&delivery.only(), directory.is_some());
}

#[test]
fn actual_sdk_error_is_returned_and_failed_record_is_retained() {
    let account = account();
    let mut payload: TransactionPayload = account.prepare_transaction(draft()).unwrap();
    let expected = payload.authority().clone();
    let other_key =
        iroha_crypto::KeyPair::try_from_seed(vec![0x5A; 32], iroha_crypto::Algorithm::Ed25519)
            .expect("deterministic public fixture key");
    let other = iroha_data_model::account::AccountId::new(other_key.public_key().clone());
    payload.authority = other.clone();
    let before = norito::encode_canonical(&payload).unwrap();
    let (context, directory) = harness();
    let (sink, delivery) = Delivery::new(directory.as_deref(), "sdk-signature-refusal");
    let result = observe(context, "sdk.transaction.authority_refusal", sink, |_| {
        account.sign_transaction(payload.clone())
    });
    assert!(
        matches!(result, Err(Error::TransactionSigning(TransactionSigningError::AuthorityMismatch { expected: actual_expected, actual })) if actual_expected == expected && actual == other)
    );
    assert_eq!(norito::encode_canonical(&payload).unwrap(), before);
    let record = delivery.only();
    assert_eq!(record.outcome, RunOutcome::Failed);
    assert_eq!(record.failures.entries.len(), 1);
    assert_eq!(record.failures.entries[0].stage, "sdk_operation");
    assert_eq!(record.failures.entries[0].code, "sdk_error");
    assert!(record.findings().iter().any(|finding| matches!(
        finding,
        Finding::RunNotSucceeded {
            outcome: RunOutcome::Failed
        }
    )));
}

#[test]
fn sdk_unwind_is_retained_and_next_actual_call_remains_usable() {
    let account = account();
    let payload = account.prepare_transaction(draft()).unwrap();
    let expected = account
        .sign_transaction(payload.clone())
        .unwrap()
        .encode_wire_v1()
        .unwrap();
    let (context, directory) = harness();
    let (sink, delivery) = Delivery::new(directory.as_deref(), "sdk-unwind");
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _: iroha::Result<()> = observe(context, "sdk.transaction.unwind", sink, |_| {
            account.sign_transaction(payload.clone())?;
            panic!("public SDK diagnostic unwind control");
        });
    }));
    assert!(unwound.is_err());
    let record = delivery.only();
    assert_eq!(record.outcome, RunOutcome::Unwound);
    assert_eq!(record.phase_tree.nodes[0].unwound, 1);
    assert!(record.findings().iter().any(|finding| matches!(
        finding,
        Finding::RunNotSucceeded {
            outcome: RunOutcome::Unwound
        }
    )));
    // The failed session has retired. Neither signing custody nor the next
    // independent recorder can be stranded by diagnostic unwinding.
    let (sink, next) = Delivery::new(None, "sdk-after-unwind");
    let actual = observe(
        RunContext::unbound(),
        "sdk.transaction.after_unwind",
        sink,
        |session| {
            for _ in 1..REPETITIONS {
                let signed = account.sign_transaction(payload.clone())?;
                assert_eq!(signed.encode_wire_v1().unwrap(), expected);
            }
            let signed = account.sign_transaction(payload)?;
            session.record_work("completed_sdk_signatures", REPETITIONS);
            Ok::<_, Error>(signed)
        },
    )
    .unwrap();
    assert_eq!(actual.encode_wire_v1().unwrap(), expected);
    successful(&next.only(), false);
}
