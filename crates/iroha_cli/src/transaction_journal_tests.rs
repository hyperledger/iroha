//! Focused custody, exact-envelope, dispatch-ambiguity and read-only recovery tests.
use super::*;
use clap::Parser as _;
use iroha_crypto::{Hash, HashOf, MerkleProof};
use iroha_data_model::{
    Level,
    block::execution_output::{ExecutionOutputV1, NetworkExecutionOutputV1},
    isi::Log,
    nexus::FeeDebitSource,
    query::CommittedTransaction,
    transaction::{DataTriggerSequence, FeePaymentIntent, TransactionBuilder, TransactionResult},
};
use iroha_model_base::topology::DataSpaceId;
use iroha_torii_shared::{FeeQuoteDecision, FeeQuoteObservation, PipelineTransactionStatus};
use norito::json;
use std::{cell::Cell, time::Duration};

fn fixture(message: &str) -> (Config, SignedTransaction, PreparedOperation) {
    let config = crate::fallback_config();
    let intent = FeePaymentIntent::authority(Vec::new(), None);
    let mut builder =
        TransactionBuilder::new(config.network_id, config.account.clone(), intent.clone())
            .with_instructions([Log::new(Level::INFO, message.to_owned())]);
    builder.set_creation_time(Duration::from_millis(1_000));
    builder.set_ttl(Duration::from_millis(120_000));
    let transaction = builder.try_sign(config.key_pair.private_key()).unwrap();
    let quote = FeeQuoteResponse {
        intent,
        observation: FeeQuoteObservation {
            ledger_time_ms: 1,
            next_block_height: 2,
            route_dataspace_id: DataSpaceId::UNIVERSAL,
        },
        components: Vec::new(),
        capacities: Vec::new(),
        decision: FeeQuoteDecision::Accepted {
            debit_source: FeeDebitSource::Account(config.account.clone()),
            program_revision: None,
        },
    };
    let operation = PreparedOperation::new(&config, &transaction, quote).unwrap();
    (config, transaction, operation)
}

fn status(hash: &str, kind: &str, resolved_from: &str) -> PipelineTransactionStatusResponse {
    PipelineTransactionStatusResponse {
        hash: hash.to_owned(),
        scope: "global".to_owned(),
        resolved_from: resolved_from.to_owned(),
        status: PipelineTransactionStatus {
            kind: kind.to_owned(),
            block_height: Some(42),
        },
    }
}

fn details(transaction: SignedTransaction) -> PipelineTransactionDetailsResponse {
    let output = ExecutionOutputV1::Network(NetworkExecutionOutputV1 {
        input_index: 0,
        result: TransactionResult::new(Ok(DataTriggerSequence::default())),
        completions: Vec::new(),
    });
    PipelineTransactionDetailsResponse {
        hash: transaction.hash_as_entrypoint().to_string(),
        transaction: CommittedTransaction {
            block_hash: HashOf::from_untyped_unchecked(Hash::new(b"journal fixture")),
            entrypoint_hash: transaction.hash_as_entrypoint(),
            entrypoint_proof: MerkleProof::from_audit_path(0, Vec::new()),
            entrypoint: TransactionEntrypoint::External(transaction),
            output_hash: HashOf::new(&output),
            output_proof: MerkleProof::from_audit_path(0, Vec::new()),
            output,
        },
    }
}

#[test]
fn prepared_record_roundtrips_exact_wire_and_rejects_substitution() {
    let (config, transaction, operation) = fixture("original");
    let bytes = canonical_bytes(&operation).unwrap();
    let decoded: PreparedOperation = json::from_slice(&bytes).unwrap();
    assert_eq!(
        decoded.validate(&config).unwrap().encode_wire_v1().unwrap(),
        transaction.encode_wire_v1().unwrap()
    );
    for defect in 0..7 {
        let mut changed = operation.clone();
        match defect {
            0 => changed.schema.push('x'),
            1 => changed.transaction_hash = "ab".repeat(32),
            2 => {
                changed.signed_transaction_wire_hex =
                    changed.signed_transaction_wire_hex.to_uppercase()
            }
            3 => changed.chain_id.push('x'),
            4 => changed.chain_discriminant ^= 1,
            5 => changed.torii_url = "https://different.invalid/".to_owned(),
            _ => {
                changed.signed_transaction_wire_hex =
                    fixture("substituted").2.signed_transaction_wire_hex
            }
        }
        assert!(changed.validate(&config).is_err(), "defect {defect}");
    }
    let mut changed_config = config;
    changed_config.account = iroha_test_samples::BOB_ID.clone();
    assert!(operation.validate(&changed_config).is_err());
}

#[test]
fn endpoint_identity_never_persists_url_credentials_or_ambiguous_components() {
    let (mut config, _, _) = fixture("endpoint");
    for value in [
        "https://user:secret@example.com/",
        "https://example.com/?token=secret",
        "https://example.com/#fragment",
        "file:///tmp/not-a-peer",
    ] {
        config.torii_api_url = value.parse().unwrap();
        assert!(endpoint_identity(&config).is_err());
    }
    config.torii_api_url = "https://taira.sora.org/".parse().unwrap();
    assert_eq!(
        endpoint_identity(&config).unwrap(),
        "https://taira.sora.org/"
    );
}

#[test]
fn failed_dispatch_is_durable_and_never_repeated_after_reopen() {
    let (_, transaction, operation) = fixture("ambiguous");
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("operation");
    let journal = Journal::create_prepared(&path, &operation).unwrap();
    let sends = Cell::new(0);
    assert!(
        dispatch_once(&journal, &operation, &transaction, 2_000, || {
            assert!(
                journal.submission_recorded(&operation).unwrap(),
                "intent must predate dispatch"
            );
            let retained: PreparedOperation = journal.read_operation().unwrap();
            assert_eq!(
                retained.signed_transaction_wire_hex,
                operation.signed_transaction_wire_hex
            );
            sends.set(sends.get() + 1);
            Err(eyre!("lost response after dispatch"))
        })
        .is_err()
    );
    drop(journal);
    let reopened = Journal::open(&path).unwrap();
    assert!(
        !dispatch_once(&reopened, &operation, &transaction, u64::MAX, || {
            sends.set(sends.get() + 1);
            Ok(())
        })
        .unwrap()
    );
    assert_eq!(sends.get(), 1);
}

#[test]
fn intent_only_crash_and_success_both_prevent_another_dispatch() {
    let (_, transaction, operation) = fixture("intent");
    for before_dispatch_crash in [true, false] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("operation");
        let journal = Journal::create_prepared(&path, &operation).unwrap();
        let sends = Cell::new(0);
        if before_dispatch_crash {
            assert!(journal.record_submission(&operation).unwrap());
        } else {
            assert!(
                dispatch_once(&journal, &operation, &transaction, 2_000, || {
                    sends.set(sends.get() + 1);
                    Ok(())
                })
                .unwrap()
            );
        }
        drop(journal);
        let reopened = Journal::open(&path).unwrap();
        assert!(
            !dispatch_once(&reopened, &operation, &transaction, 2_000, || {
                sends.set(sends.get() + 1);
                Ok(())
            })
            .unwrap()
        );
        assert_eq!(sends.get(), usize::from(!before_dispatch_crash));
    }
}

#[test]
fn expiry_and_original_mismatch_refuse_dispatch_before_intent() {
    let (_, transaction, operation) = fixture("expiry");
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("operation");
    let journal = Journal::create_prepared(&path, &operation).unwrap();
    assert_eq!(execution_expiry(&transaction).unwrap(), 121_000);
    assert!(
        dispatch_once(&journal, &operation, &transaction, 121_000, || panic!(
            "expired POST"
        ))
        .is_err()
    );
    assert!(!journal.submission_recorded(&operation).unwrap());
    let other = fixture("foreign").2;
    assert!(
        dispatch_once(&journal, &other, &transaction, 2_000, || panic!(
            "foreign POST"
        ))
        .is_err()
    );
    assert!(!journal.submission_recorded(&operation).unwrap());
    assert!(
        Journal::create(&path).is_err(),
        "prepare must never overwrite an original"
    );
    assert!(now_ms().unwrap() > 0);
}

#[test]
fn only_exact_global_state_status_can_reach_applied() {
    let (_, _, operation) = fixture("status");
    let hash = &operation.transaction_hash;
    assert_eq!(classify_status(hash, None).unwrap().state, "Absent");
    for kind in ["Applied", "Rejected", "Expired"] {
        assert_eq!(
            classify_status(hash, Some(&status(hash, kind, "cache")))
                .unwrap()
                .state,
            "Pending"
        );
        assert_eq!(
            classify_status(hash, Some(&status(hash, kind, "state")))
                .unwrap()
                .state,
            kind
        );
    }
    for kind in ["Queued", "Approved", "Committed"] {
        assert_eq!(
            classify_status(hash, Some(&status(hash, kind, "queue")))
                .unwrap()
                .state,
            "Pending"
        );
    }
    for defect in 0..5 {
        let mut changed = status(hash, "Applied", "state");
        match defect {
            0 => changed.hash = "cd".repeat(32),
            1 => changed.scope = "local".to_owned(),
            2 => changed.status.block_height = Some(0),
            3 => changed.status.kind = "Unknown".to_owned(),
            _ => changed.resolved_from = "unverified".to_owned(),
        }
        assert!(classify_status(hash, Some(&changed)).is_err());
    }
}

#[test]
fn applied_details_must_contain_the_original_signed_envelope() {
    let (_, transaction, _) = fixture("exact");
    verify_committed(&transaction, &details(transaction.clone())).unwrap();
    let other = fixture("other").1;
    assert!(verify_committed(&transaction, &details(other)).is_err());
    let mut changed = details(transaction.clone());
    changed.hash = "ff".repeat(32);
    assert!(verify_committed(&transaction, &changed).is_err());
}

#[test]
fn journal_grammar_requires_preparation_fee_and_rejects_recovery_overrides() {
    let preparing = Args::try_parse_from([
        "iroha",
        "--fee-payer",
        "authority",
        "tx",
        "prepare",
        "--journal",
        "/private/operation",
    ])
    .unwrap();
    validate_globals(&preparing).unwrap();
    let no_fee =
        Args::try_parse_from(["iroha", "tx", "prepare", "--journal", "/private/operation"])
            .unwrap();
    assert!(validate_globals(&no_fee).is_err());
    for action in ["submit", "resume"] {
        let args = Args::try_parse_from(["iroha", "tx", action, "--journal", "/private/operation"])
            .unwrap();
        validate_globals(&args).unwrap();
        let args = Args::try_parse_from([
            "iroha",
            "--fee-payer",
            "authority",
            "tx",
            action,
            "--journal",
            "/private/operation",
        ])
        .unwrap();
        assert!(validate_globals(&args).is_err());
        let args = Args::try_parse_from([
            "iroha",
            "--metadata",
            "/private/metadata",
            "tx",
            action,
            "--journal",
            "/private/operation",
        ])
        .unwrap();
        assert!(validate_globals(&args).is_err());
    }
    let args = Args::try_parse_from([
        "iroha",
        "--emit-instructions",
        "--fee-payer",
        "authority",
        "tx",
        "prepare",
        "--journal",
        "/private/operation",
    ])
    .unwrap();
    assert!(validate_globals(&args).is_err());
    let args = Args::try_parse_from([
        "iroha",
        "--verbose",
        "tx",
        "resume",
        "--journal",
        "/private/operation",
    ])
    .unwrap();
    assert!(validate_globals(&args).is_err());
}

#[test]
fn retained_applied_evidence_without_the_original_intent_never_authorizes_dispatch() {
    let (_, transaction, operation) = fixture("unexpected evidence");
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("operation");
    let journal = Journal::create_prepared(&path, &operation).unwrap();
    journal
        .write_applied_evidence(&norito::json!({"unexpected": true}))
        .unwrap();
    assert!(
        dispatch_once(&journal, &operation, &transaction, 2_000, || panic!(
            "unexpected POST"
        ))
        .is_err()
    );
    assert!(!journal.submission_recorded(&operation).unwrap());
}

#[derive(Debug)]
struct ReadOnlyTransport {
    requests: std::sync::Mutex<Vec<iroha::http::TransportRequest>>,
    response: std::sync::Mutex<Option<iroha::http::Response<Vec<u8>>>>,
}
impl iroha::http::HttpTransport for ReadOnlyTransport {
    fn send_blocking(
        &self,
        request: iroha::http::TransportRequest,
    ) -> Result<iroha::http::Response<Vec<u8>>> {
        assert_eq!(
            request.method,
            iroha::http::Method::GET,
            "recovery must not POST"
        );
        assert_eq!(request.url.path(), "/v1/pipeline/transactions/status");
        self.requests.lock().unwrap().push(request);
        self.response
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| eyre!("unexpected recovery request"))
    }
    fn send(&self, request: iroha::http::TransportRequest) -> iroha::http::TransportFuture<'_> {
        Box::pin(async move { self.send_blocking(request) })
    }
}

struct ReadOnlyContext {
    config: Config,
    client: Client,
    i18n: iroha_i18n::Localizer,
    output: Option<json::Value>,
}
impl RunContext for ReadOnlyContext {
    fn config(&self) -> &Config {
        &self.config
    }
    fn transaction_metadata(&self) -> Option<&iroha_model_base::metadata::Metadata> {
        None
    }
    fn input_instructions(&self) -> bool {
        false
    }
    fn output_instructions(&self) -> bool {
        false
    }
    fn i18n(&self) -> &iroha_i18n::Localizer {
        &self.i18n
    }
    fn client_from_config(&self) -> Result<Client> {
        Ok(self.client.clone())
    }
    fn print_data<T: JsonSerialize + ?Sized>(&mut self, value: &T) -> Result<()> {
        self.output = Some(json::to_value(value)?);
        Ok(())
    }
    fn println(&mut self, _value: impl std::fmt::Display) -> Result<()> {
        panic!("unexpected text output")
    }
}

#[test]
fn resume_and_repeated_submit_make_only_a_status_read_and_do_not_change_the_journal() {
    let (config, _, operation) = fixture("read-only");
    for may_submit in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("operation");
        let journal = Journal::create_prepared(&path, &operation).unwrap();
        assert!(journal.record_submission(&operation).unwrap());
        let before = ["operation.json", "submission.json"]
            .map(|name| std::fs::read(path.join(name)).unwrap());
        drop(journal);
        let response = iroha::http::Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(json::to_vec(&status(&operation.transaction_hash, "Applied", "cache")).unwrap())
            .unwrap();
        let transport = std::sync::Arc::new(ReadOnlyTransport {
            requests: std::sync::Mutex::new(Vec::new()),
            response: std::sync::Mutex::new(Some(response)),
        });
        let client = Client::builder(config.clone())
            .http_transport(transport.clone())
            .build()
            .unwrap();
        let mut context = ReadOnlyContext {
            config: config.clone(),
            client,
            i18n: iroha_i18n::Localizer::new(
                iroha_i18n::Bundle::Cli,
                iroha_i18n::Language::English,
            ),
            output: None,
        };
        assert!(
            run_retained(
                JournalArgs {
                    journal: path.clone()
                },
                &mut context,
                may_submit
            )
            .is_err()
        );
        assert_eq!(transport.requests.lock().unwrap().len(), 1);
        let report = context.output.unwrap();
        assert_eq!(
            report.get("state").and_then(json::Value::as_str),
            Some("Pending")
        );
        assert_eq!(
            report
                .get("exact_committed_envelope_verified")
                .and_then(json::Value::as_bool),
            Some(false)
        );
        let after = ["operation.json", "submission.json"]
            .map(|name| std::fs::read(path.join(name)).unwrap());
        assert_eq!(before, after);
        assert_eq!(
            std::fs::read_dir(&path).unwrap().count(),
            3,
            "no recovery records may be written"
        );
    }
}
