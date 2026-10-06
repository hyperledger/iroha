//! Four-validator rejection until the complete IVM execution relation is admitted.
//!
//! A normal contract call establishes a live counter. Fresh signed IvmProved
//! requests at every peer must yield the exact unavailable-relation rejection,
//! exact typed admission or committed results and unchanged state after an Applied barrier.
//! Native alias, corruption and forged-witness coverage belongs to the retained
//! relation tests; this case does not claim a complete execution proof.
use super::{
    contract_probe_call_intent, contract_state_json_value, deploy_contract_artifact,
    wait_for_tx_applied,
};
use eyre::{Report, Result, ensure, eyre};
use integration_tests::sandbox;
use iroha::{
    blocking::Client,
    client::{AccountTransactionDraft, FeeQuoteRequest, TransactionFinalityFailure},
    query::QueryError,
};
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{
    Level, ValidationFail,
    isi::{Grant, InstructionBox, Log},
    permission::Permission,
    query::error::QueryExecutionFail,
    smart_contract::{ContractAddress, ContractAlias},
    transaction::{
        Executable, FeePaymentIntent, IvmBytecode, IvmProved, SignedTransaction,
        TransactionEntrypoint, error::TransactionRejectionReason,
    },
};
use iroha_executor_data_model::permission::{
    account::{AccountAliasPermissionScope, CanManageAccountAlias},
    governance::CanEnactGovernance,
    smart_contract::CanManageSmartContractCode,
};
use iroha_model_base::{metadata::Metadata, topology::DataSpaceId};
use iroha_test_network::{Network, NetworkBuilder, read_on_dedicated_thread};
use iroha_test_samples::ALICE_ID;
use std::{num::NonZeroU32, time::Duration};

const TEST_NAME: &str =
    "four_validator_ivm_proved_rejects_unavailable_execution_and_preserves_state";
const OBSERVATION_TIMEOUT: Duration = Duration::from_secs(600);
const EXECUTION_UNAVAILABLE: &str =
    "zk_proof: IvmProved requires the complete native STARK execution relation";

fn counter_artifact() -> Vec<u8> {
    kotodama_lang::compiler::Compiler::new_with_options(kotodama_lang::compiler::CompilerOptions {
        force_zk: true,
        max_cycles: 4_096,
        ..Default::default()
    })
    .compile_source(
        r#"seiyaku ProvedCounter {
  state StateMap<int, int> Counters;
  kotoage fn bump() authorize("CanEnactGovernance") {
    let current = Counters.get(7).unwrap_or(0);
    Counters[7] = current + 1;
  }
}"#,
    )
    .expect("compile the real zero-argument counter with the ZK mode bit")
}

fn bounded_client(client: Client) -> Client {
    integration_tests::sync::rebind_blocking_client(&client, |configured| {
        configured.transaction_status_timeout = OBSERVATION_TIMEOUT;
        configured.torii_request_timeout = Duration::from_secs(90);
        configured.transaction_ttl = Some(Duration::from_secs(660));
    })
}

async fn transaction(
    client: &Client,
    executable: Executable,
    metadata: &Metadata,
    fee_payment: &FeePaymentIntent,
    nonce: u32,
) -> Result<SignedTransaction> {
    let account = client.account_client();
    let mut payload = account.prepare_transaction(
        AccountTransactionDraft::new(executable, fee_payment.clone(), metadata.clone())
            .with_time_to_live(Duration::from_secs(660)),
    )?;
    payload.nonce = Some(NonZeroU32::new(nonce).expect("nonzero test nonce"));
    // Quote this exact draft before signing. Core fee_bound_for_admission_payload
    // meters IvmProved using its signed gas limit and overlay count; it does not
    // execute the unavailable relation. A quote/fee failure cannot pass this test.
    let quote = tokio::time::timeout(
        OBSERVATION_TIMEOUT,
        account.quote_fees(FeeQuoteRequest::AccountSignature { payload: &payload }),
    )
    .await
    .map_err(|_| eyre!("exact transaction fee quote timed out"))??;
    ensure!(
        payload
            .fee_payment
            .has_same_payer_and_gas_bound(&quote.intent),
        "fee quote changed selected payer or gas limit"
    );
    payload.fee_payment = quote.intent;
    Ok(account.sign_transaction(payload)?)
}

async fn applied_everywhere(
    network: &Network,
    http: &reqwest::Client,
    hash: HashOf<SignedTransaction>,
    label: &str,
) -> Result<()> {
    tokio::time::timeout(OBSERVATION_TIMEOUT, async {
        let hash = hex::encode(hash.as_ref());
        let mut common_height = None;
        for peer in network.peers() {
            let height = wait_for_tx_applied(
                http,
                peer.client().client().endpoint(),
                &hash,
                OBSERVATION_TIMEOUT,
                label,
            )
            .await?;
            if let Some(expected) = common_height {
                ensure!(height == expected, "validators disagree on Applied height");
            }
            common_height = Some(height);
        }
        Ok(())
    })
    .await
    .map_err(|_| eyre!("{label}: all-peer Applied observations exceeded the shared deadline"))?
}

async fn counter_everywhere(
    network: &Network,
    http: &reqwest::Client,
    address: &ContractAddress,
    expected: &str,
) -> Result<()> {
    tokio::time::timeout(OBSERVATION_TIMEOUT, async {
        for (index, peer) in network.peers().iter().enumerate() {
            let value = contract_state_json_value(
                http,
                peer.client().client().endpoint(),
                address,
                "Counters/7",
            )
            .await?;
            ensure!(
                value == norito::json::Value::from(expected),
                "validator {index} counter changed: {value:?}"
            );
        }
        Ok(())
    })
    .await
    .map_err(|_| eyre!("all-peer counter observations exceeded the shared deadline"))?
}

fn require_exact_rejection(
    result: Result<HashOf<SignedTransaction>>,
    expected: &str,
) -> Result<()> {
    let error = result
        .err()
        .ok_or_else(|| eyre!("invalid proved transaction was Applied"))?;
    let Some(TransactionRejectionReason::Validation(ValidationFail::NotPermitted(message))) =
        error.downcast_ref::<TransactionRejectionReason>()
    else {
        return Err(eyre!(
            "transport, timeout, fee or unrelated rejection cannot establish proof rejection: {error:?}"
        ));
    };
    ensure!(
        message == expected,
        "wrong native rejection: {message:?}, expected {expected:?}"
    );
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RejectionEvidence {
    Admission,
    Committed,
}

async fn require_authenticated_rejection(
    client: &Client,
    transaction: &SignedTransaction,
    result: Result<HashOf<SignedTransaction>>,
    expected: &str,
) -> Result<RejectionEvidence> {
    let error = result
        .err()
        .ok_or_else(|| eyre!("invalid proved transaction was Applied"))?;
    if error.downcast_ref::<TransactionRejectionReason>().is_some() {
        // A typed response to this exact signed submission can reject before
        // persistence. Do not invent a committed transaction-details record.
        require_exact_rejection(Err(error), expected)?;
        return Ok(RejectionEvidence::Admission);
    }
    let failure = error
        .downcast_ref::<TransactionFinalityFailure>()
        .ok_or_else(|| {
            eyre!(
                "proof rejection requires a typed native result, not transport failure: {error:?}"
            )
        })?;
    failure.validate_for_hash(transaction.hash())?;
    ensure!(
        failure.response().status.kind == "Rejected",
        "expiry is not proof rejection"
    );
    committed_rejection_on_peer(client, transaction, expected).await?;
    Ok(RejectionEvidence::Committed)
}

async fn committed_rejection_on_peer(
    client: &Client,
    transaction: &SignedTransaction,
    expected: &str,
) -> Result<()> {
    let entrypoint_hash = transaction.hash_as_entrypoint();
    tokio::time::timeout(OBSERVATION_TIMEOUT, async {
        loop {
            let details = read_on_dedicated_thread({
                let client = client.clone();
                move || {
                    client
                        .client()
                        .get_transaction_details(entrypoint_hash)
                        .map_err(Report::new)
                }
            })
            .await;
            let details = match details {
                Ok(details) => details,
                Err(error)
                    if matches!(
                        error.downcast_ref::<QueryError>(),
                        Some(QueryError::Validation(ValidationFail::QueryFailed(
                            QueryExecutionFail::NotFound | QueryExecutionFail::CapacityLimit
                        )))
                    ) =>
                {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                }
                Err(error) => return Err(error),
            };
            // The normal signed details API already validates the canonical
            // source/output binding. Also require the exact original signed
            // payload, not merely another rejection at the requested height.
            ensure!(
                details.transaction.entrypoint_hash() == &entrypoint_hash,
                "wrong details entrypoint"
            );
            let TransactionEntrypoint::External(committed) = details.transaction.entrypoint()
            else {
                return Err(eyre!(
                    "rejection details must contain an external signed transaction"
                ));
            };
            ensure!(
                committed == transaction,
                "rejection details changed the signed transaction"
            );
            let reason = details
                .transaction
                .result()
                .0
                .as_ref()
                .err()
                .ok_or_else(|| eyre!("rejection details contain a successful result"))?;
            return require_exact_rejection(Err(eyre!(reason.clone())), expected);
        }
    })
    .await
    .map_err(|_| eyre!("authenticated rejection details exceeded the shared deadline"))?
}

async fn rejected_unchanged_everywhere(
    network: &Network,
    http: &reqwest::Client,
    address: &ContractAddress,
    metadata: &Metadata,
    fee_payment: &FeePaymentIntent,
    proved: &IvmProved,
    case: u32,
    label: &str,
) -> Result<()> {
    // Fresh signed identities exercise each peer's ingress without reusing a
    // prior request. Routing may forward admission to an authoritative peer;
    // this does not establish which validator performed the local execution.
    for (index, peer) in network.peers().iter().enumerate() {
        let client = bounded_client(peer.client());
        let transaction = transaction(
            &client,
            Executable::IvmProved(proved.clone()),
            metadata,
            fee_payment,
            100 + 4 * case + u32::try_from(index)?,
        )
        .await?;
        let result = read_on_dedicated_thread({
            let client = client.clone();
            let transaction = transaction.clone();
            move || client.submit_transaction_and_wait(&transaction)
        })
        .await;
        let evidence =
            require_authenticated_rejection(&client, &transaction, result, EXECUTION_UNAVAILABLE)
                .await?;
        // A committed result must converge on every validator. An exact typed
        // admission refusal need not have a persisted transaction record.
        if evidence == RejectionEvidence::Committed {
            for observer in network.peers() {
                committed_rejection_on_peer(
                    &bounded_client(observer.client()),
                    &transaction,
                    EXECUTION_UNAVAILABLE,
                )
                .await?;
            }
        }
    }
    // An independently Applied barrier rules out stalled validators. Its own
    // ordinary log effect is unrelated to the counter under test.
    let client = bounded_client(network.client());
    let label_owned = label.to_owned();
    let hash = read_on_dedicated_thread(move || {
        client.submit(
            Log::new(
                Level::INFO,
                format!("IvmProved rejection barrier {label_owned}"),
            ),
            FeePaymentIntent::authority(Vec::new(), None),
        )
    })
    .await?;
    applied_everywhere(network, http, hash, label).await?;
    counter_everywhere(network, http, address, "1").await
}

#[test]
#[ignore = "requires same-candidate daemon and mandatory four-validator rejection observations"]
fn four_validator_ivm_proved_rejects_unavailable_execution_and_preserves_state() -> Result<()> {
    ensure!(
        std::env::var("IROHA_TEST_REQUIRE_NETWORK").as_deref() == Ok("1"),
        "this qualification requires IROHA_TEST_REQUIRE_NETWORK=1"
    );
    let worker = std::thread::Builder::new()
        .name(TEST_NAME.into())
        .stack_size(64 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .enable_all()
                .build()?
                .block_on(run())
        })?;
    match worker.join() {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

async fn run() -> Result<()> {
    let alias = ContractAlias::from_components("proved_counter", None, "universal")?;
    let alias_permission = CanManageAccountAlias {
        scope: AccountAliasPermissionScope::Alias(
            iroha_data_model::alias_setup::ResolvedAccountAliasV1::new(
                "proved_counter@universal".parse()?,
                DataSpaceId::UNIVERSAL,
            ),
        ),
    };
    let mut builder = NetworkBuilder::new()
        .with_peers(4)
        .with_auto_populated_trusted_peers();
    for permission in [
        Permission::from(CanManageSmartContractCode),
        Permission::from(CanEnactGovernance),
        Permission::from(alias_permission),
    ] {
        builder = builder
            .with_genesis_instruction(Grant::account_permission(permission, ALICE_ID.clone()));
    }
    let network = sandbox::start_network_async_or_skip(builder, TEST_NAME)
        .await?
        .ok_or_else(|| eyre!("required four-validator native network was skipped"))?;
    ensure!(
        network.peers().len() == 4,
        "expected exactly four validators"
    );
    network.ensure_blocks(1).await?;
    let client = bounded_client(network.client());
    let http = integration_tests::http::client();
    let artifact = counter_artifact();
    let parsed = ivm::ProgramMetadata::parse(&artifact)?;
    let gas_limit = iroha_core::smartcontracts::ivm::gas_limit_for_meta(&parsed.metadata)
        .map_err(|error| eyre!("counter gas limit: {error:?}"))?;
    let fee_payment = FeePaymentIntent::authority(Vec::new(), std::num::NonZeroU64::new(gas_limit));
    let (address, _, height) = deploy_contract_artifact(
        &client,
        &http,
        &artifact,
        "proved_counter",
        "deploy unavailable-relation counter",
    )
    .await?;
    network.ensure_blocks(height).await?;
    let intent = contract_probe_call_intent(&artifact, &address, &alias, "bump")?;
    // A supported ordinary call proves the deployed code, authority, fee path,
    // entrypoint and state readback work before testing unavailable admission.
    let ordinary = transaction(
        &client,
        Executable::ContractCall(intent.invocation),
        &intent.metadata,
        &fee_payment,
        1,
    )
    .await?;
    let hash = read_on_dedicated_thread({
        let client = client.clone();
        move || client.submit_transaction_and_wait(&ordinary)
    })
    .await?;
    applied_everywhere(&network, &http, hash, "ordinary counter call").await?;
    counter_everywhere(&network, &http, &address, "1").await?;
    let mut proposed = IvmProved {
        bytecode: IvmBytecode::from_compiled(artifact),
        overlay: Vec::<InstructionBox>::new().into(),
        events_commitment: Hash::new(b"unavailable execution events"),
        gas_policy_commitment: Hash::new(b"unavailable execution gas policy"),
    };
    rejected_unchanged_everywhere(
        &network,
        &http,
        &address,
        &intent.metadata,
        &fee_payment,
        &proposed,
        0,
        "empty claimed overlay",
    )
    .await?;
    proposed.overlay =
        vec![Log::new(Level::INFO, "unproved claimed effect".to_owned()).into()].into();
    proposed.events_commitment = Hash::new(b"different unproved events");
    proposed.gas_policy_commitment = Hash::new(b"different unproved gas policy");
    rejected_unchanged_everywhere(
        &network,
        &http,
        &address,
        &intent.metadata,
        &fee_payment,
        &proposed,
        1,
        "nonempty claimed overlay and different commitments",
    )
    .await?;
    Ok(())
}

#[test]
fn counter_fixture_uses_real_v1_interface_and_zk_mode() -> Result<()> {
    let artifact = counter_artifact();
    let parsed = ivm::ProgramMetadata::parse(&artifact)?;
    ensure!(
        parsed.metadata.mode & ivm::ivm_mode::ZK != 0,
        "ZK mode missing"
    );
    let verified = ivm::verify_contract_artifact(&artifact).map_err(|error| eyre!("{error}"))?;
    ensure!(
        verified
            .contract_interface
            .entrypoints
            .iter()
            .any(|entry| entry.name == "bump" && entry.params.is_empty()),
        "exact no-argument entrypoint missing"
    );
    Ok(())
}

#[test]
fn unavailable_relation_rejection_rejects_transport_and_unrelated_native_errors() {
    let rejection = |message: &str| {
        eyre!(TransactionRejectionReason::Validation(
            ValidationFail::NotPermitted(message.to_owned())
        ))
    };
    require_exact_rejection(Err(rejection(EXECUTION_UNAVAILABLE)), EXECUTION_UNAVAILABLE).unwrap();
    assert!(
        require_exact_rejection(
            Err(eyre!("transport: {EXECUTION_UNAVAILABLE}")),
            EXECUTION_UNAVAILABLE
        )
        .is_err()
    );
    assert!(require_exact_rejection(Err(rejection("fee refused")), EXECUTION_UNAVAILABLE).is_err());
    assert!(
        require_exact_rejection(
            Err(rejection("zk_proof: malformed proof")),
            EXECUTION_UNAVAILABLE
        )
        .is_err()
    );
}
