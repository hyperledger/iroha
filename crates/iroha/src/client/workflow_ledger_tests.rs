//! The workflow ledger adapter over the mock HTTP transport: the real requests and responses of
//! the existing submission and global-status owners, without a network.

use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex},
    time::Duration,
};

use iroha_torii_shared::{ErrorDetails, ErrorEnvelope};
use iroha_version::codec::{DecodeVersioned as _, EncodeVersioned as _};

use super::{
    APPLICATION_NORITO, AccountClient, AccountTransactionDraft, AccountWorkflowContext, Client,
    FeePaymentIntent, InstructionBox, Metadata, Response, SignedTransaction, StatusCode,
    capabilities_body_with, compatible_capabilities_body,
    evidence_http_tests::{
        base_url, client_with_base_url, json_response, mark_data_model_compatible,
        scoped_pipeline_absence,
    },
    mk_response,
    transaction_dispatch_error::{DEFINITE_DISPATCH_ROWS, DefiniteDispatchResult},
};
use crate::{
    http::Method,
    http_default::{DefaultHttpTransport, RequestSnapshot},
    workflow::{
        BuiltStepPayload, CommittedOutcome, DispatchOutcome, DriverIdentityV1,
        MemoryWorkflowStorage, StepContext, StepDescriptorV1, StepFailure, TransactionIdentityV1,
        WorkflowAccount, WorkflowDriver, WorkflowErrorCode, WorkflowFuture, WorkflowKindV1,
        WorkflowLedger, WorkflowRequest, WorkflowRunOptions, WorkflowStage, WorkflowStatusV1,
        WorkflowStorage, authority_binding_text, domain_digest,
    },
};

type Scripted = core::result::Result<Response<Vec<u8>>, &'static str>;
type Snapshots = Arc<Mutex<Vec<RequestSnapshot>>>;

/// A client whose transport answers exactly the scripted responses, in order.
fn scripted(responses: Vec<Scripted>, compatible: bool) -> (AccountClient, Snapshots) {
    let responses = Arc::new(Mutex::new(VecDeque::from(responses)));
    let snapshots: Snapshots = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&snapshots);
    let transport = DefaultHttpTransport::mock(Arc::new(move |snapshot| {
        observed.lock().expect("snapshots").push(snapshot);
        match responses.lock().expect("responses").pop_front() {
            Some(Ok(response)) => Ok(response),
            Some(Err(failure)) => Err(eyre::eyre!(failure)),
            None => panic!("unscripted HTTP request"),
        }
    }));
    let client: Client = client_with_base_url(base_url()).with_test_http_transport(transport);
    if compatible {
        mark_data_model_compatible(&client);
    }
    (client.account_client().expect("account context"), snapshots)
}

fn context_of(account: AccountClient) -> AccountWorkflowContext {
    AccountWorkflowContext::new(account).expect("the authority has a canonical address payload")
}

fn signed(account: &AccountClient) -> (SignedTransaction, Vec<u8>, TransactionIdentityV1) {
    let payload = account
        .prepare_transaction(AccountTransactionDraft::new(
            Vec::<InstructionBox>::new(),
            FeePaymentIntent::authority(Vec::new(), None),
            Metadata::default(),
        ))
        .expect("payload");
    let transaction = account.sign_transaction(payload).expect("signed");
    let bytes = transaction.encode_versioned();
    let identity = context_of(account.clone())
        .identify(&bytes)
        .expect("identity");
    (transaction, bytes, identity)
}

fn rejection(
    status: u16,
    envelope_code: &str,
    header: Option<&str>,
    details_code: Option<&str>,
) -> Response<Vec<u8>> {
    let envelope = ErrorEnvelope::new(envelope_code, "scripted").with_details(ErrorDetails {
        reject_code: details_code.map(str::to_owned),
        ..ErrorDetails::default()
    });
    let mut response = json_response(
        StatusCode::from_u16(status).expect("status"),
        &String::from_utf8(norito::json::to_vec(&envelope).expect("envelope")).expect("UTF-8"),
    );
    if let Some(header) = header {
        response
            .headers_mut()
            .insert("x-iroha-reject-code", header.parse().expect("header"));
    }
    response
}

async fn dispatch_one(response: Scripted) -> (DispatchOutcome, Vec<RequestSnapshot>, Vec<u8>) {
    let (account, snapshots) = scripted(vec![response], true);
    let (_, bytes, identity) = signed(&account);
    let outcome = context_of(account).dispatch(&bytes, &identity).await;
    let snapshots = std::mem::take(&mut *snapshots.lock().expect("snapshots"));
    (outcome, snapshots, bytes)
}

#[tokio::test]
async fn dispatch_classification_follows_the_closed_non_admission_table() {
    // Acknowledgements.
    for status in [StatusCode::ACCEPTED, StatusCode::OK] {
        let (outcome, snapshots, bytes) =
            dispatch_one(Ok(mk_response(status, Vec::new(), None))).await;
        assert_eq!(outcome, DispatchOutcome::Accepted);
        // Exactly one request carrying exactly the persisted signed bytes.
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].method, Method::POST);
        assert_eq!(snapshots[0].body, bytes);
    }
    // Every row of the closed table, as Torii emits it.
    for row in DEFINITE_DISPATCH_ROWS {
        let details = row.details_repeat_reject_code.then_some(row.reject_code);
        let (outcome, snapshots, _) = dispatch_one(Ok(rejection(
            row.status,
            row.envelope_code,
            Some(row.reject_code),
            details,
        )))
        .await;
        assert_eq!(snapshots.len(), 1, "{}", row.envelope_code);
        match row.result {
            DefiniteDispatchResult::AlreadyKnown => {
                assert_eq!(
                    outcome,
                    DispatchOutcome::AlreadyKnown,
                    "{}",
                    row.envelope_code
                );
            }
            DefiniteDispatchResult::Refused => assert!(
                matches!(outcome, DispatchOutcome::Refused { .. }),
                "{}: {outcome:?}",
                row.envelope_code
            ),
            DefiniteDispatchResult::Deferred => assert!(
                matches!(
                    outcome,
                    DispatchOutcome::NotAdmitted {
                        code: WorkflowErrorCode::LocalResourceUnavailable,
                        ..
                    }
                ),
                "{}: {outcome:?}",
                row.envelope_code
            ),
        }
    }
    // The same refusal in the canonical Norito representation.
    let envelope =
        ErrorEnvelope::new("transaction_expired", "scripted").with_details(ErrorDetails {
            reject_code: Some("ED07".to_owned()),
            ..ErrorDetails::default()
        });
    let mut norito_refusal = mk_response(
        StatusCode::BAD_REQUEST,
        norito::to_bytes(&envelope).expect("envelope"),
        Some(APPLICATION_NORITO),
    );
    norito_refusal
        .headers_mut()
        .insert("x-iroha-reject-code", "ED07".parse().expect("header"));
    assert!(matches!(
        dispatch_one(Ok(norito_refusal)).await.0,
        DispatchOutcome::Refused { .. }
    ));

    // Everything else proves nothing about admission and stays ambiguous.
    let mut spaced = rejection(400, "transaction_expired", Some("ED07"), Some("ED07"));
    spaced.body_mut().push(b' ');
    let mut duplicated = rejection(400, "transaction_expired", Some("ED07"), Some("ED07"));
    duplicated
        .headers_mut()
        .append("x-iroha-reject-code", "ED07".parse().expect("header"));
    let ambiguous: Vec<(&str, Scripted)> = vec![
        ("transport failure", Err("connection reset")),
        (
            "bare 500",
            Ok(mk_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                Vec::new(),
                None,
            )),
        ),
        (
            "gateway timeout",
            Ok(mk_response(
                StatusCode::GATEWAY_TIMEOUT,
                b"timeout".to_vec(),
                None,
            )),
        ),
        (
            "node-side queue failure",
            Ok(rejection(
                503,
                "queue_admission_invariant",
                Some("PRTRY:QUEUE_ADMISSION_INVARIANT"),
                Some("PRTRY:QUEUE_ADMISSION_INVARIANT"),
            )),
        ),
        (
            "unlisted code",
            Ok(rejection(400, "something_new", Some("NEW"), Some("NEW"))),
        ),
        (
            "listed code without its header",
            Ok(rejection(400, "transaction_expired", None, Some("ED07"))),
        ),
        (
            "listed code with another header",
            Ok(rejection(
                400,
                "transaction_expired",
                Some("PRTRY:QUEUE_FULL"),
                Some("ED07"),
            )),
        ),
        (
            "listed code without its details code",
            Ok(rejection(400, "transaction_expired", Some("ED07"), None)),
        ),
        (
            "listed code under another status",
            Ok(rejection(
                409,
                "transaction_expired",
                Some("ED07"),
                Some("ED07"),
            )),
        ),
        ("non-canonical body", Ok(spaced)),
        ("duplicated header", Ok(duplicated)),
        (
            "bare 400",
            Ok(mk_response(StatusCode::BAD_REQUEST, Vec::new(), None)),
        ),
        (
            "request timeout",
            Ok(mk_response(StatusCode::REQUEST_TIMEOUT, Vec::new(), None)),
        ),
    ];
    for (name, response) in ambiguous {
        let (outcome, snapshots, _) = dispatch_one(response).await;
        assert!(
            matches!(outcome, DispatchOutcome::Ambiguous { .. }),
            "{name}: {outcome:?}"
        );
        assert_eq!(snapshots.len(), 1, "{name}: dispatched at most once");
    }
}

#[tokio::test]
async fn a_dispatch_that_never_left_the_client_is_reported_by_its_cause() {
    // Bytes that are not a canonical signed transaction: nothing is sent.
    let (account, snapshots) = scripted(Vec::new(), true);
    let (_, bytes, identity) = signed(&account);
    let context = context_of(account);
    let mut trailing = bytes.clone();
    trailing.push(0);
    for foreign in [b"garbage".to_vec(), trailing] {
        let outcome = context.dispatch(&foreign, &identity).await;
        assert!(
            matches!(
                outcome,
                DispatchOutcome::NotAdmitted {
                    code: WorkflowErrorCode::NonCanonicalEncoding,
                    ..
                }
            ),
            "{outcome:?}"
        );
    }
    // Canonical bytes under another identity are refused before dispatch too.
    let mut other = identity;
    other.signed_transaction_hash[0] ^= 0x10;
    assert!(matches!(
        context.dispatch(&bytes, &other).await,
        DispatchOutcome::NotAdmitted {
            code: WorkflowErrorCode::NonCanonicalEncoding,
            ..
        }
    ));
    assert!(snapshots.lock().expect("snapshots").is_empty());

    // A node with another data model: the capability probe is the only request.
    let (account, snapshots) = scripted(
        vec![Ok(json_response(
            StatusCode::OK,
            &capabilities_body_with(Some(u32::MAX), None),
        ))],
        false,
    );
    let (_, bytes, identity) = signed(&account);
    let outcome = context_of(account).dispatch(&bytes, &identity).await;
    assert!(
        matches!(
            outcome,
            DispatchOutcome::NotAdmitted {
                code: WorkflowErrorCode::UnsupportedOperation,
                ..
            }
        ),
        "{outcome:?}"
    );
    {
        let snapshots = snapshots.lock().expect("snapshots");
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].method, Method::GET);
    }

    // A probe that cannot be completed is a local resource failure, and nothing is posted.
    let (account, snapshots) = scripted(vec![Err("probe connection refused")], false);
    let (_, bytes, identity) = signed(&account);
    let outcome = context_of(account).dispatch(&bytes, &identity).await;
    assert!(
        matches!(
            outcome,
            DispatchOutcome::NotAdmitted {
                code: WorkflowErrorCode::LocalResourceUnavailable,
                ..
            }
        ),
        "{outcome:?}"
    );
    assert!(
        snapshots
            .lock()
            .expect("snapshots")
            .iter()
            .all(|snapshot| snapshot.method == Method::GET)
    );

    // A compatible probe is followed by exactly one post.
    let (account, snapshots) = scripted(
        vec![
            Ok(json_response(
                StatusCode::OK,
                &compatible_capabilities_body(),
            )),
            Ok(mk_response(StatusCode::ACCEPTED, Vec::new(), None)),
        ],
        false,
    );
    let (_, bytes, identity) = signed(&account);
    assert_eq!(
        context_of(account).dispatch(&bytes, &identity).await,
        DispatchOutcome::Accepted
    );
    let methods = snapshots
        .lock()
        .expect("snapshots")
        .iter()
        .map(|snapshot| snapshot.method.clone())
        .collect::<Vec<_>>();
    assert_eq!(methods, [Method::GET, Method::POST]);
}

fn status(hash: &str, kind: &str, resolved_from: &str, scope: &str) -> Response<Vec<u8>> {
    let status = if kind == "Applied" {
        norito::json!({"kind": kind, "block_height": 7})
    } else {
        norito::json!({"kind": kind})
    };
    let payload = norito::json!({
        "hash": hash,
        "status": status,
        "scope": scope,
        "resolved_from": resolved_from
    });
    json_response(
        StatusCode::OK,
        &norito::json::to_string(&payload).expect("status JSON"),
    )
}

#[tokio::test]
async fn committed_outcome_requires_a_state_resolved_global_status() {
    let (account, _) = scripted(Vec::new(), true);
    let (transaction, _, identity) = signed(&account);
    let hash = transaction.hash();
    let text = hash.to_string();
    let other = {
        let mut bytes = identity.signed_transaction_hash;
        bytes[0] ^= 0x20;
        hex::encode(bytes)
    };
    let cases: Vec<(&str, Scripted, CommittedOutcome)> = vec![
        (
            "exact absence",
            Ok(scoped_pipeline_absence(&hash)),
            CommittedOutcome::ExactAbsence,
        ),
        (
            "state-resolved applied",
            Ok(status(&text, "Applied", "state", "global")),
            CommittedOutcome::Applied {
                block_height: Some(7),
            },
        ),
        (
            "state-resolved expired",
            Ok(status(&text, "Expired", "state", "global")),
            CommittedOutcome::Expired,
        ),
        // Terminal kinds that are not resolved from state are hints.
        (
            "cached applied",
            Ok(status(&text, "Applied", "cache", "global")),
            CommittedOutcome::ObservedNotFinal,
        ),
        (
            "cached rejected",
            Ok(status(&text, "Rejected", "cache", "global")),
            CommittedOutcome::ObservedNotFinal,
        ),
        (
            "queued expired",
            Ok(status(&text, "Expired", "queue", "global")),
            CommittedOutcome::ObservedNotFinal,
        ),
        (
            "queued",
            Ok(status(&text, "Queued", "queue", "global")),
            CommittedOutcome::ObservedNotFinal,
        ),
        (
            "approved",
            Ok(status(&text, "Approved", "state", "global")),
            CommittedOutcome::ObservedNotFinal,
        ),
        (
            "committed",
            Ok(status(&text, "Committed", "state", "global")),
            CommittedOutcome::ObservedNotFinal,
        ),
    ];
    for (name, response, expected) in cases {
        let (account, snapshots) = scripted(vec![response], true);
        let outcome = context_of(account).committed_outcome(&identity).await;
        assert_eq!(outcome, expected, "{name}");
        // Reconciliation is one exact global read of the original identity. It never posts.
        let snapshots = snapshots.lock().expect("snapshots");
        assert_eq!(snapshots.len(), 1, "{name}");
        assert_eq!(snapshots[0].method, Method::GET, "{name}");
        assert_eq!(snapshots[0].url.path(), "/v1/pipeline/transactions/status");
        let query = snapshots[0]
            .url
            .query_pairs()
            .into_owned()
            .collect::<BTreeMap<_, _>>();
        assert_eq!(query.get("hash"), Some(&text), "{name}");
        assert_eq!(
            query.get("scope").map(String::as_str),
            Some("global"),
            "{name}"
        );
    }
    let (account, _) = scripted(vec![Ok(status(&text, "Rejected", "state", "global"))], true);
    assert!(matches!(
        context_of(account).committed_outcome(&identity).await,
        CommittedOutcome::Rejected { .. }
    ));

    // A response that is not bound to this identity and scope, or not a status at all,
    // is a failed read: it neither closes the identity nor proves absence.
    let failed: Vec<(&str, Scripted)> = vec![
        (
            "another hash",
            Ok(status(&other, "Applied", "state", "global")),
        ),
        (
            "local scope",
            Ok(status(&text, "Applied", "state", "local")),
        ),
        (
            "unknown source",
            Ok(status(&text, "Applied", "ledger", "global")),
        ),
        (
            "unknown kind",
            Ok(status(&text, "Finalised", "state", "global")),
        ),
        (
            "untyped 404",
            Ok(mk_response(StatusCode::NOT_FOUND, Vec::new(), None)),
        ),
        (
            "server error",
            Ok(mk_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                Vec::new(),
                None,
            )),
        ),
        (
            "backpressure",
            Ok(json_response(StatusCode::TOO_MANY_REQUESTS, "{}")),
        ),
        ("transport failure", Err("connection reset")),
    ];
    for (name, response) in failed {
        let (account, snapshots) = scripted(vec![response], true);
        let outcome = context_of(account).committed_outcome(&identity).await;
        assert!(
            matches!(outcome, CommittedOutcome::ReadFailed { .. }),
            "{name}: {outcome:?}"
        );
        assert!(
            snapshots
                .lock()
                .expect("snapshots")
                .iter()
                .all(|snapshot| snapshot.method == Method::GET),
            "{name}"
        );
    }
}

#[tokio::test]
async fn signing_and_identity_come_from_the_account_context() {
    let (account, _) = scripted(Vec::new(), true);
    let context = context_of(account.clone());
    let binding = context.binding();
    assert_eq!(binding.network, account.network_id().to_string());
    // The authority text is the domain-separated hash of the canonical address payload.
    let address = crate::account_address::AccountAddress::from_account_id(account.authority())
        .expect("address")
        .canonical_bytes()
        .expect("canonical payload");
    assert_eq!(binding.authority, authority_binding_text(&address));
    assert_eq!(
        binding.authority,
        hex::encode(domain_digest(
            b"iroha:durable-workflow:authority:v1\0",
            &[&address]
        ))
    );
    assert_eq!(binding.authority.len(), 64);
    assert!(
        binding
            .authority
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );

    let payload = account
        .prepare_transaction(AccountTransactionDraft::new(
            Vec::<InstructionBox>::new(),
            FeePaymentIntent::authority(Vec::new(), None),
            Metadata::default(),
        ))
        .expect("payload");
    let unsigned = norito::encode_canonical(&payload).expect("canonical payload");
    let signed = context.sign(&unsigned).await.expect("signed");
    let transaction =
        SignedTransaction::decode_all_versioned(&signed.signed_transaction).expect("transaction");
    assert_eq!(transaction.payload(), &payload);
    assert_eq!(
        signed.identity.signed_transaction_hash,
        *iroha_crypto::Hash::from(transaction.hash()).as_ref()
    );
    assert_eq!(
        signed.identity.entrypoint_hash,
        *iroha_crypto::Hash::from(transaction.hash_as_entrypoint()).as_ref()
    );
    assert_eq!(
        context.identify(&signed.signed_transaction),
        Ok(signed.identity)
    );

    // Bytes that are not exactly one canonical value are refused.
    let mut trailing = signed.signed_transaction.clone();
    trailing.push(0);
    for foreign in [b"garbage".to_vec(), trailing] {
        assert_eq!(
            context.identify(&foreign).expect_err("not canonical").code,
            WorkflowErrorCode::NonCanonicalEncoding
        );
    }
    let mut padded = unsigned.clone();
    padded.push(0);
    for foreign in [b"garbage".to_vec(), padded] {
        assert_eq!(
            context
                .sign(&foreign)
                .await
                .expect_err("not canonical")
                .code,
            WorkflowErrorCode::NonCanonicalEncoding
        );
    }
    // A payload of another authority is never signed by this context.
    let (stranger, _) = scripted(Vec::new(), true);
    let foreign = stranger
        .prepare_transaction(AccountTransactionDraft::new(
            Vec::<InstructionBox>::new(),
            FeePaymentIntent::authority(Vec::new(), None),
            Metadata::default(),
        ))
        .expect("payload");
    assert_eq!(
        context
            .sign(&norito::encode_canonical(&foreign).expect("canonical payload"))
            .await
            .expect_err("foreign authority")
            .code,
        WorkflowErrorCode::BindingMismatch
    );
}

#[test]
fn signing_failures_map_to_typed_codes() {
    use crate::{Error as SdkError, TransactionSigningError};

    let (account, _) = scripted(Vec::new(), true);
    let authority = account.authority().clone();
    let cases = [
        (
            TransactionSigningError::DirectSigningUnavailable {
                authority: authority.clone(),
            },
            WorkflowErrorCode::UnsupportedOperation,
        ),
        (
            TransactionSigningError::AuthorityNotDirect {
                authority: authority.clone(),
            },
            WorkflowErrorCode::UnsupportedOperation,
        ),
        (
            TransactionSigningError::AuthorityMismatch {
                expected: authority.clone(),
                actual: authority,
            },
            WorkflowErrorCode::BindingMismatch,
        ),
    ];
    for (error, code) in cases {
        let failure = super::workflow_ledger::signing_failure(&SdkError::from(error));
        assert_eq!(failure.code, code, "{}", failure.detail);
    }
    // Anything that is not a signing-domain error is a local failure, never a rejection.
    assert_eq!(
        super::workflow_ledger::signing_failure(&SdkError::Timeout { operation: "sign" }).code,
        WorkflowErrorCode::LocalResourceUnavailable
    );
}

/// A capability driver that builds one real, empty transaction payload per identity.
struct PayloadDriver {
    account: AccountClient,
}

impl WorkflowDriver for PayloadDriver {
    fn identity(&self) -> DriverIdentityV1 {
        DriverIdentityV1 {
            id: "adapter-test-driver".to_owned(),
            schema_version: 1,
        }
    }

    fn build_transaction<'a>(
        &'a self,
        context: StepContext<'a>,
    ) -> WorkflowFuture<'a, core::result::Result<BuiltStepPayload, StepFailure>> {
        Box::pin(async move {
            let payload = self
                .account
                .prepare_transaction(AccountTransactionDraft::new(
                    Vec::<InstructionBox>::new(),
                    FeePaymentIntent::authority(Vec::new(), None),
                    Metadata::default(),
                ))
                .map_err(|error| {
                    StepFailure::new(WorkflowErrorCode::InvalidInput, error.to_string())
                })?;
            Ok(BuiltStepPayload {
                intent_digest: context.descriptor.intent_digest,
                unsigned_payload: norito::encode_canonical(&payload).map_err(|error| {
                    StepFailure::new(WorkflowErrorCode::InvalidInput, error.to_string())
                })?,
            })
        })
    }
}

fn request(account: &AccountClient, instance: &str) -> WorkflowRequest {
    WorkflowRequest {
        instance: instance.to_owned(),
        driver: PayloadDriver {
            account: account.clone(),
        }
        .identity(),
        request_context_digest: [7; 32],
        steps: vec![StepDescriptorV1::transaction("register", [9; 32])],
    }
}

#[tokio::test]
async fn the_named_workflow_calls_are_distinct_durable_handles() {
    let (account, _) = scripted(Vec::new(), true);
    let storage: Arc<dyn WorkflowStorage> = Arc::new(MemoryWorkflowStorage::new());
    let bootstrap = account
        .bootstrap_workflow(request(&account, "one"), Arc::clone(&storage))
        .expect("bootstrap");
    let key_generation = account
        .dkg_workflow(request(&account, "one"), Arc::clone(&storage))
        .expect("key generation");
    let opening = account
        .threshold_opening_workflow(request(&account, "one"), Arc::clone(&storage))
        .expect("opening");
    assert_eq!(bootstrap.plan().kind, WorkflowKindV1::IssuerBootstrap);
    assert_eq!(key_generation.plan().kind, WorkflowKindV1::Dkg);
    assert_eq!(opening.plan().kind, WorkflowKindV1::ThresholdOpening);
    // The kind is bound into the identifier: one request, three different workflows.
    assert_ne!(bootstrap.id(), key_generation.id());
    assert_ne!(bootstrap.id(), opening.id());
    assert_ne!(key_generation.id(), opening.id());
    // The same call rebuilds the same handle.
    assert_eq!(
        account
            .bootstrap_workflow(request(&account, "one"), Arc::clone(&storage))
            .expect("bootstrap")
            .id(),
        bootstrap.id()
    );
    let mut invalid = request(&account, "one");
    invalid.steps.clear();
    assert_eq!(
        account
            .dkg_workflow(invalid, storage)
            .expect_err("invalid plan")
            .code,
        WorkflowErrorCode::InvalidInput
    );
}

#[tokio::test]
async fn a_bootstrap_workflow_resumes_through_the_existing_owners_without_resubmitting() {
    // First call: the post times out, then the global status is exactly absent.
    // Second call: the first request is the status read of the original identity.
    // The reads are answered from the hash of the recorded request, because the signed
    // identity exists only after the first call signs.
    let snapshots: Snapshots = Arc::new(Mutex::new(Vec::new()));
    let script: Arc<Mutex<VecDeque<&'static str>>> = Arc::new(Mutex::new(
        ["timeout", "absent", "applied"].into_iter().collect(),
    ));
    let recorded = Arc::clone(&snapshots);
    let remaining = Arc::clone(&script);
    let transport = DefaultHttpTransport::mock(Arc::new(move |snapshot: RequestSnapshot| {
        let step = remaining
            .lock()
            .expect("script")
            .pop_front()
            .expect("unscripted HTTP request");
        let hash = snapshot
            .url
            .query_pairs()
            .find(|(key, _)| key == "hash")
            .map(|(_, value)| value.into_owned());
        recorded.lock().expect("snapshots").push(snapshot);
        match (step, hash) {
            ("timeout", None) => Err(eyre::eyre!("request timed out")),
            ("absent", Some(hash)) => {
                let hash: iroha_crypto::Hash = hash.parse().expect("hash");
                Ok(scoped_pipeline_absence(
                    &super::HashOf::from_untyped_unchecked(hash),
                ))
            }
            ("applied", Some(hash)) => Ok(status(&hash, "Applied", "state", "global")),
            (step, hash) => panic!("unexpected request for `{step}`: {hash:?}"),
        }
    }));
    let client: Client = client_with_base_url(base_url()).with_test_http_transport(transport);
    mark_data_model_compatible(&client);
    let account = client.account_client().expect("account context");
    let driver = PayloadDriver {
        account: account.clone(),
    };
    let storage: Arc<dyn WorkflowStorage> = Arc::new(MemoryWorkflowStorage::new());
    let options = WorkflowRunOptions {
        observation_timeout: Duration::ZERO,
        ..WorkflowRunOptions::default()
    };
    let handle = account
        .bootstrap_workflow(request(&account, "resume"), Arc::clone(&storage))
        .expect("handle");

    let error = handle.run(&driver, &options).await.expect_err("unknown");
    assert_eq!(
        (error.code, error.stage),
        (
            WorkflowErrorCode::SubmissionOutcomeUnknown,
            WorkflowStage::Reconcile
        )
    );
    let identity = *error.transaction.expect("identity");
    let progress = error.progress.expect("progress");
    assert_eq!(progress.steps[0].state, "outcome_unknown");
    assert!(progress.is_partially_complete());
    assert_eq!(progress.atomicity, "per_transaction_only");

    // A handle rebuilt from the same request resumes the same workflow.
    let resumed = account
        .bootstrap_workflow(request(&account, "resume"), storage)
        .expect("handle");
    assert_eq!(resumed.id(), handle.id());
    let completed = resumed.run(&driver, &options).await.expect("completed");
    assert_eq!(completed.status, WorkflowStatusV1::Completed);
    assert_eq!(
        completed.steps[0].identities[0].identity,
        Some(identity),
        "the workflow finished under its original transaction identity"
    );
    assert_eq!(completed.steps[0].identities.len(), 1);

    let snapshots = snapshots.lock().expect("snapshots");
    let methods = snapshots
        .iter()
        .map(|snapshot| snapshot.method.clone())
        .collect::<Vec<_>>();
    // One post in total. Everything after the ambiguous post is a read.
    assert_eq!(methods, [Method::POST, Method::GET, Method::GET]);
    let expected_hash = hex::encode(identity.signed_transaction_hash);
    for read in &snapshots[1..] {
        assert_eq!(read.url.path(), "/v1/pipeline/transactions/status");
        assert!(
            read.url
                .query_pairs()
                .any(|(key, value)| key == "hash" && value == expected_hash.as_str())
        );
    }
    assert!(script.lock().expect("script").is_empty());
}

/// The quoted string literals of `text`, in order.
fn string_literals(text: &str) -> Vec<&str> {
    text.split('"').skip(1).step_by(2).collect()
}

fn first_literal(arm: &str) -> Option<&str> {
    string_literals(arm).first().copied()
}

fn status_name(arm: &str) -> Option<&str> {
    arm.split("StatusCode::")
        .nth(1)?
        .split(|character: char| !(character.is_ascii_uppercase() || character == '_'))
        .next()
}

/// `variant -> value` for each arm of the `match` in the body of `function`.
fn match_arms<'a>(
    source: &'a str,
    function: &str,
    value: fn(&'a str) -> Option<&'a str>,
) -> BTreeMap<&'a str, &'a str> {
    let start = source
        .find(&format!("fn {function}("))
        .unwrap_or_else(|| panic!("`{function}` not found in the Torii source"));
    let body = &source[start..];
    let end = body[1..]
        .find("\n    fn ")
        .or_else(|| body[1..].find("\nfn "))
        .map_or(body.len(), |end| end + 1);
    let chunks = body[..end].split("=>").collect::<Vec<_>>();
    let mut arms = BTreeMap::new();
    for pair in chunks.windows(2) {
        let Some(found) = value(pair[1]) else {
            continue;
        };
        for pattern in pair[0].split("queue::Error::").skip(1) {
            let variant = pattern
                .split(|character: char| !character.is_ascii_alphanumeric())
                .next()
                .expect("variant");
            arms.insert(variant, found);
        }
    }
    arms
}

#[test]
fn the_non_admission_table_classifies_every_torii_queue_rejection() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../iroha_torii/src/queue_rejection_metadata.rs");
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    let statuses = match_arms(&source, "status_code_for_queue_error", status_name);
    let envelope_codes = match_arms(&source, "queue_error_summary", first_literal);
    let reject_codes = match_arms(&source, "queue_rejection_metadata", first_literal);
    assert!(statuses.len() >= 18, "{statuses:?}");
    assert_eq!(
        statuses.keys().collect::<Vec<_>>(),
        envelope_codes.keys().collect::<Vec<_>>()
    );
    assert_eq!(
        statuses.keys().collect::<Vec<_>>(),
        reject_codes.keys().collect::<Vec<_>>()
    );
    // Node-side failures prove nothing about admission and must stay outside the table.
    let node_side = [
        "AdmissionInvariant",
        "Governance",
        "NexusFeeAdmissionConfigInvalid",
    ];
    let status_number = |name: &str| match name {
        "BAD_REQUEST" => 400,
        "FORBIDDEN" => 403,
        "CONFLICT" => 409,
        "UNPROCESSABLE_ENTITY" => 422,
        "TOO_MANY_REQUESTS" => 429,
        "INTERNAL_SERVER_ERROR" => 500,
        "SERVICE_UNAVAILABLE" => 503,
        other => panic!("unmapped Torii status `{other}`"),
    };
    let mut classified = Vec::new();
    for (variant, status) in &statuses {
        let status = status_number(status);
        let envelope_code = envelope_codes[variant];
        let reject_code = reject_codes[variant];
        let row = DEFINITE_DISPATCH_ROWS
            .iter()
            .find(|row| row.envelope_code == envelope_code);
        if node_side.contains(variant) {
            assert!(status >= 500, "{variant}");
            assert!(row.is_none(), "{variant} must stay ambiguous");
            continue;
        }
        let row = row.unwrap_or_else(|| {
            panic!("Torii queue rejection `{variant}` ({envelope_code}) is not classified")
        });
        assert_eq!(row.status, status, "{variant}");
        assert_eq!(row.reject_code, reject_code, "{variant}");
        // Only the deferral omits the reject code from the envelope details.
        assert_eq!(
            row.details_repeat_reject_code,
            *variant != "Deferred",
            "{variant}"
        );
        let expected = match *variant {
            "InBlockchain" | "IsInQueue" => DefiniteDispatchResult::AlreadyKnown,
            "Deferred" | "Full" | "LatencySaturated" | "MaximumTransactionsPerUser" => {
                DefiniteDispatchResult::Deferred
            }
            _ => DefiniteDispatchResult::Refused,
        };
        assert_eq!(row.result, expected, "{variant}");
        classified.push(row.envelope_code);
    }
    // No row exists that Torii's queue does not emit.
    for row in DEFINITE_DISPATCH_ROWS {
        assert!(
            classified.contains(&row.envelope_code),
            "`{}` is not a Torii queue rejection",
            row.envelope_code
        );
        assert!((400..500).contains(&row.status));
    }
    assert_eq!(classified.len(), DEFINITE_DISPATCH_ROWS.len());
}
