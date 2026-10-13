//! Real four-validator final Kaigi authorization/usage lifecycle and persisted replay rejection.
//!
//! Governed keys are installed through signed RegisterVerifyingKey instructions. Every proof
//! binds the actual network identity and the latest identical call record fetched from all peers.
//! The standard revision-4 RS16 path, exact four/three equal-vote committee and production proof budgets
//! remain enabled. The only resource override is one GiB of ordinary local storage per validator.
//! TODO: Compile and execute against the exact retained daemon before claiming deployment evidence.

use super::privacy_exact12_network_support::{run_network_case, wait_for_transaction_on_peers};
use eyre::{Result, WrapErr as _, ensure, eyre};
use integration_tests::sandbox;
use iroha::{
    blocking::Client,
    client::{AccountTransactionDraft, FeeQuoteRequest},
};
use iroha_core::privacy_release_evidence::kaigi::{
    KaigiAuthorizationActionV1, build_kaigi_release_authorization_v1, build_kaigi_release_usage_v1,
    kaigi_release_verifier_references_v1, kaigi_release_verifier_registrations_v1,
};
use iroha_crypto::HashOf;
use iroha_data_model::{
    Level, NetworkId, ValidationFail,
    account::Account,
    domain::Domain,
    isi::{
        Grant, InstructionBox, Log, Register, Transfer,
        error::{InstructionExecutionError, InvalidParameterError},
    },
    kaigi::{KaigiId, KaigiPrivacyMode, KaigiRecord, KaigiStatus, NewKaigi, kaigi_metadata_key},
    prelude::{AssetId, FindDomainById, HasMetadata},
    transaction::{FeePaymentIntent, SignedTransaction, error::TransactionRejectionReason},
};
use iroha_executor_data_model::permission::governance::CanManageVerifyingKeys;
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name::Name;
use iroha_primitives::json::Json;
use iroha_test_network::{NetworkBuilder, init_instruction_registry, read_on_dedicated_thread};
use iroha_test_samples::{ALICE_ID, gen_account_in};
use std::time::Duration;
use tokio::time::{Instant, sleep, timeout};

const TEST_NAME: &str = "four_validator_kaigi_private_lifecycle_replay_and_restart";
const SUBMIT_TIMEOUT: Duration = Duration::from_secs(180);
const CONVERGENCE_TIMEOUT: Duration = Duration::from_secs(180);
const RESTART_TIMEOUT: Duration = Duration::from_secs(120);

fn bounded_client(client: Client) -> Client {
    integration_tests::sync::rebind_blocking_client(&client, |configured| {
        configured.transaction_status_timeout = SUBMIT_TIMEOUT;
        configured.torii_request_timeout = Duration::from_secs(45);
        configured.transaction_ttl = Some(Duration::from_secs(300));
    })
}

async fn prepare(
    client: &Client,
    label: &str,
    instructions: Vec<InstructionBox>,
) -> Result<SignedTransaction> {
    let mut metadata = Metadata::default();
    metadata.insert("kaigi_release_step".parse::<Name>()?, Json::new(label));
    let account = client.account_client();
    let mut payload = account.prepare_transaction(AccountTransactionDraft::new(
        instructions,
        FeePaymentIntent::authority(Vec::new(), None),
        metadata,
    ))?;
    let quote = timeout(
        SUBMIT_TIMEOUT,
        account.quote_fees(FeeQuoteRequest::AccountSignature { payload: &payload }),
    )
    .await
    .map_err(|_| eyre!("{label}: fee quote timed out"))??;
    ensure!(
        payload
            .fee_payment
            .has_same_payer_and_gas_bound(&quote.intent),
        "fee quote changed payer or gas bound"
    );
    payload.fee_payment = quote.intent;
    Ok(account.sign_transaction(payload)?)
}

async fn submit_exact(
    client: &Client,
    transaction: &SignedTransaction,
) -> Result<HashOf<SignedTransaction>> {
    timeout(
        SUBMIT_TIMEOUT,
        client
            .account_client()
            .submit_transaction_and_wait(transaction),
    )
    .await
    .map_err(|_| eyre!("Kaigi signed submission timed out"))?
}

async fn applied(
    clients: &[Client],
    signer: &Client,
    label: &str,
    instructions: Vec<InstructionBox>,
) -> Result<SignedTransaction> {
    let transaction = prepare(signer, label, instructions).await?;
    let hash = submit_exact(signer, &transaction)
        .await
        .wrap_err_with(|| format!("{label}: signed instruction must be Applied"))?;
    ensure!(
        hash == transaction.hash(),
        "Applied response substituted the transaction hash"
    );
    wait_for_transaction_on_peers(clients, &transaction, label, CONVERGENCE_TIMEOUT).await?;
    Ok(transaction)
}

async fn read_record(client: &Client, call: &KaigiId) -> Result<Option<KaigiRecord>> {
    let client = client.clone();
    let call = call.clone();
    read_on_dedicated_thread(move || {
        let domain = client
            .client()
            .query_single(FindDomainById::new(call.domain_id.clone()))?;
        let key = kaigi_metadata_key(&call.call_name)?;
        domain
            .metadata()
            .get(&key)
            .cloned()
            .map(|value| {
                value
                    .try_into_any_norito::<KaigiRecord>()
                    .map_err(Into::into)
            })
            .transpose()
    })
    .await
}

async fn identical_records(
    clients: &[Client],
    call: &KaigiId,
    expected: Option<&KaigiRecord>,
) -> Result<Option<KaigiRecord>> {
    let deadline = Instant::now() + CONVERGENCE_TIMEOUT;
    loop {
        let mut records = Vec::with_capacity(clients.len());
        for client in clients {
            records.push(read_record(client, call).await?);
        }
        if records.iter().all(|record| record == &records[0]) {
            if let Some(expected) = expected {
                ensure!(
                    records[0].as_ref() == Some(expected),
                    "all peers converged to a mutated Kaigi record"
                );
            }
            return Ok(records.remove(0));
        }
        ensure!(
            Instant::now() < deadline,
            "Kaigi records did not converge before deadline"
        );
        sleep(Duration::from_millis(200)).await;
    }
}

// Mutate only the native transcript. Canonical framing, public inputs and
// verifier identity remain unchanged, so the network tests cryptographic failure.
fn corrupt_native_proof(proof: &[u8]) -> Result<Vec<u8>> {
    use iroha_data_model::zk::{BackendTag, NativePipaRProofV1, OpenVerifyEnvelope};
    let mut envelope: OpenVerifyEnvelope = norito::decode_canonical(proof)?;
    ensure!(
        envelope.backend == BackendTag::NativePipaRPasta,
        "expected native PIPA-R fixture"
    );
    let mut carrier: NativePipaRProofV1 = norito::decode_canonical(&envelope.proof_bytes)?;
    ensure!(!carrier.proof.is_empty(), "fixture has no native proof");
    let middle = carrier.proof.len() / 2;
    carrier.proof[middle] ^= 1;
    envelope.proof_bytes = norito::encode_canonical(&carrier)?;
    Ok(norito::encode_canonical(&envelope)?)
}

fn require_native_rejection(
    result: Result<HashOf<SignedTransaction>>,
    expected: &str,
) -> Result<()> {
    let error = result
        .err()
        .ok_or_else(|| eyre!("invalid Kaigi action was Applied"))?;
    let Some(TransactionRejectionReason::Validation(ValidationFail::InstructionFailed(reason))) =
        error.downcast_ref::<TransactionRejectionReason>()
    else {
        return Err(eyre!(
            "transport, timeout, fee or unrelated rejection cannot establish Kaigi proof rejection: {error:?}"
        ));
    };
    let message: &str = match reason {
        InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
            message,
        )) => message,
        InstructionExecutionError::InvariantViolation(message) => message,
        _ => return Err(eyre!("wrong native Kaigi rejection category: {reason:?}")),
    };
    ensure!(
        message == expected,
        "expected exact native {expected:?}, got {message:?}"
    );
    Ok(())
}

async fn rejected_unchanged(
    clients: &[Client],
    host: &Client,
    signer: &Client,
    call: &KaigiId,
    label: &str,
    instruction: InstructionBox,
    expected_error: &str,
    expected: Option<&KaigiRecord>,
) -> Result<()> {
    let transaction = prepare(signer, label, vec![instruction]).await?;
    require_native_rejection(submit_exact(signer, &transaction).await, expected_error)?;
    // An independently Applied barrier separates a real rejection from a stalled node.
    applied(
        clients,
        host,
        &format!("{label}-barrier"),
        vec![Log::new(Level::INFO, format!("Kaigi rejection barrier {label}")).into()],
    )
    .await?;
    let observed = identical_records(clients, call, expected).await?;
    if expected.is_none() {
        ensure!(observed.is_none(), "rejected create stored a call");
    }
    Ok(())
}

async fn common_commit(clients: &[Client]) -> Result<()> {
    let deadline = Instant::now() + CONVERGENCE_TIMEOUT;
    loop {
        let mut subjects = Vec::new();
        for client in clients {
            let client = client.clone();
            let status =
                read_on_dedicated_thread(move || client.client().get_sumeragi_status()).await?;
            ensure!(status.halted.is_none(), "fail-stopped consensus");
            subjects.push(status.committed_height);
        }
        if subjects.len() == clients.len() && subjects.iter().all(|subject| *subject == subjects[0])
        {
            return Ok(());
        }
        ensure!(
            Instant::now() < deadline,
            "four peers did not converge to one committed height"
        );
        sleep(Duration::from_millis(200)).await;
    }
}

async fn restart_persisted(
    network: &sandbox::SerializedNetwork,
    clients: &[Client],
    call: &KaigiId,
    expected: &KaigiRecord,
    label: &str,
) -> Result<()> {
    let peer = network.peers()[3].clone();
    let config_layers = network.config_layers().collect::<Vec<_>>();
    let old_pid = peer
        .process_id()
        .await
        .ok_or_else(|| eyre!("restart peer has no running process"))?;
    ensure!(
        peer.shutdown_if_started().await,
        "selected validator was not running"
    );
    let barrier = applied(
        &clients[..3],
        &clients[0],
        label,
        vec![Log::new(Level::INFO, format!("Kaigi persisted restart {label}")).into()],
    )
    .await?;
    timeout(
        RESTART_TIMEOUT,
        peer.start_checked(config_layers.iter(), None),
    )
    .await
    .map_err(|_| eyre!("Kaigi validator restart timed out"))??;
    let new_pid = peer
        .process_id()
        .await
        .ok_or_else(|| eyre!("restarted validator has no process"))?;
    ensure!(old_pid != new_pid, "restart reused the original process");
    wait_for_transaction_on_peers(clients, &barrier, label, CONVERGENCE_TIMEOUT).await?;
    identical_records(clients, call, Some(expected)).await?;
    common_commit(clients).await
}

#[test]
#[ignore = "requires an exact same-candidate daemon and an explicit real four-validator network"]
fn four_validator_kaigi_private_lifecycle_replay_and_restart() -> Result<()> {
    run_network_case(TEST_NAME, lifecycle)
}

async fn lifecycle() -> Result<()> {
    ensure!(
        std::env::var("IROHA_TEST_REQUIRE_NETWORK").as_deref() == Ok("1"),
        "real Kaigi release test requires IROHA_TEST_REQUIRE_NETWORK=1"
    );
    init_instruction_registry();
    let domain = DomainId::try_new("kaigi", "universal")?;
    let (participant, participant_key) = gen_account_in("kaigi");
    let refs = kaigi_release_verifier_references_v1();
    let registrations = kaigi_release_verifier_registrations_v1();
    // The relation-selecting Kaigi verifying keys are committed chain policy: genesis
    // installs them in `zk_validity_policy_v1`. A node configuration cannot select them.
    let mut zk_policy = iroha_core::zk_validity_policy::ZkValidityPolicyV1::protocol_default();
    let [authorization_vk, usage_vk] =
        refs.map(|key| iroha_core::zk_validity_policy::ZkVerifyingKeyRefV1 {
            backend: key.backend,
            name: key.name,
        });
    zk_policy.proofs.kaigi_authorization_vk = Some(authorization_vk);
    zk_policy.proofs.kaigi_usage_vk = Some(usage_vk);
    let builder = NetworkBuilder::new()
        .with_peers(4)
        .with_auto_populated_trusted_peers()
        .with_permissioned_consensus()
        .with_block_cadence(Duration::from_millis(100))
        .with_genesis_instruction(iroha_data_model::isi::SetParameter::new(
            iroha_data_model::parameter::Parameter::Custom(zk_policy.into_custom_parameter()),
        ))
        .with_genesis_instruction(Register::domain(Domain::new(domain.clone())))
        .with_genesis_instruction(Register::account(Account::new(participant.clone())))
        .with_genesis_instruction(Grant::account_permission(
            CanManageVerifyingKeys,
            ALICE_ID.clone(),
        ))
        .with_config_layer(move |layer| {
            layer.write(
                ["nexus", "storage", "local_budget_bytes"],
                1_073_741_824_i64,
            );
        });
    let network = sandbox::start_network_async_or_skip(builder, TEST_NAME)
        .await?
        .ok_or_else(|| eyre!("mandatory real Kaigi network was skipped"))?;
    let result: Result<()> = async {
        ensure!(
            network.peers().len() == 4,
            "Kaigi requires exactly four validators"
        );
        let clients = network
            .peers()
            .iter()
            .map(|peer| bounded_client(peer.client()))
            .collect::<Vec<_>>();
        let host = clients[0].clone();
        let member = bounded_client(
            network.peers()[0].client_for(&participant, participant_key.private_key().clone()),
        );
        let network_id: NetworkId = *host.client().network_id();
        ensure!(
            clients
                .iter()
                .all(|client| *client.client().network_id() == network_id)
                && *member.client().network_id() == network_id,
            "client network identities differ"
        );
        applied(
            &clients,
            &host,
            "register-governed-keys",
            registrations.into_iter().map(Into::into).collect(),
        )
        .await?;
        // The generated participant is a real independent signer. Fund its ordinary
        // fee asset through an Applied transfer, rather than bypassing fee admission.
        let fee_definition =
            iroha_config::parameters::defaults::nexus::fees::fee_asset_id().parse()?;
        applied(
            &clients,
            &host,
            "fund-participant-fees",
            vec![
                Transfer::asset_quantity(
                    AssetId::new(fee_definition, ALICE_ID.clone()),
                    100_000_u32,
                    participant.clone(),
                )
                .into(),
            ],
        )
        .await?;
        let mut call = NewKaigi::with_defaults(
            KaigiId::new(domain.clone(), "private_lifecycle".parse()?),
            ALICE_ID.clone(),
        );
        call.privacy_mode = KaigiPrivacyMode::ZkRosterV1;
        call.max_participants = Some(2);
        let empty = KaigiRecord::from_new(&call, 0);
        let created = build_kaigi_release_authorization_v1(
            network_id,
            &empty,
            &ALICE_ID,
            0,
            KaigiAuthorizationActionV1::HostCreate,
        );
        let mut corrupt = created.create(call.clone());
        // Preserve canonical framing and all proof bytes while changing forbidden metadata.
        let mut envelope: iroha_data_model::zk::OpenVerifyEnvelope =
            norito::decode_canonical(corrupt.proof.as_ref().unwrap())?;
        envelope.aux.push(1);
        corrupt.proof = Some(norito::encode_canonical(&envelope)?);
        rejected_unchanged(
            &clients,
            &host,
            &host,
            call.id(),
            "tampered-create",
            corrupt.into(),
            "privacy proof envelope auxiliary bytes must be empty",
            None,
        )
        .await?;
        let create_tx = applied(
            &clients,
            &host,
            "create",
            vec![created.create(call.clone()).into()],
        )
        .await?;
        let initial = identical_records(&clients, call.id(), None)
            .await?
            .ok_or_else(|| eyre!("Applied Create omitted record"))?;
        ensure!(
            initial.status == KaigiStatus::Active
                && initial.host_commitment.as_ref() == Some(&created.commitment)
                && initial.roster_commitments.is_empty()
                && initial.nullifier_log.len() == 1,
            "invalid created private state"
        );
        ensure!(
            initial.participants.is_empty(),
            "private call exposed a transparent roster"
        );
        let joined = build_kaigi_release_authorization_v1(
            network_id,
            &initial,
            &participant,
            1,
            KaigiAuthorizationActionV1::Join,
        );
        rejected_unchanged(
            &clients,
            &host,
            &host,
            call.id(),
            "host-cannot-impersonate-participant",
            joined.join(call.id(), &participant).into(),
            "private Kaigi participation must be signed by the participant",
            Some(&initial),
        )
        .await?;
        let mut invalid_join = joined.join(call.id(), &participant);
        invalid_join.proof = Some(corrupt_native_proof(&joined.proof)?);
        rejected_unchanged(
            &clients,
            &host,
            &member,
            call.id(),
            "tampered-native-join-proof",
            invalid_join.into(),
            "privacy proof verification failed",
            Some(&initial),
        )
        .await?;
        applied(
            &clients,
            &member,
            "join",
            vec![joined.join(call.id(), &participant).into()],
        )
        .await?;
        let active = identical_records(&clients, call.id(), None).await?.unwrap();
        ensure!(
            active.roster_commitments == vec![joined.commitment.clone()]
                && active.nullifier_log.len() == 2
                && active.participants.is_empty(),
            "joined roster state differs"
        );
        ensure!(
            active.private_participation.entries()[0].sequence() == 1
                && active.roster_root() != initial.roster_root(),
            "join did not bind first participation"
        );
        rejected_unchanged(
            &clients,
            &host,
            &member,
            call.id(),
            "replayed-join",
            joined.join(call.id(), &participant).into(),
            "Kaigi private subject is already active",
            Some(&active),
        )
        .await?;
        let usage = build_kaigi_release_usage_v1(network_id, &active);
        let mut altered_usage = usage.clone();
        altered_usage.billed_gas += 1;
        rejected_unchanged(
            &clients,
            &host,
            &host,
            call.id(),
            "tampered-usage",
            altered_usage.into(),
            "Kaigi usage differs from authenticated call, host, root, segment or billed tuple",
            Some(&active),
        )
        .await?;
        applied(&clients, &host, "usage", vec![usage.clone().into()]).await?;
        let used = identical_records(&clients, call.id(), None).await?.unwrap();
        ensure!(
            used.segments_recorded == 1
                && used.total_duration_ms == 1200
                && used.total_billed_gas == 345
                && used.roster_root() == active.roster_root()
                && used.nullifier_log == active.nullifier_log,
            "usage did not preserve exact roster/counters"
        );
        rejected_unchanged(
            &clients,
            &host,
            &host,
            call.id(),
            "replayed-usage",
            usage.into(),
            "Kaigi usage differs from authenticated call, host, root, segment or billed tuple",
            Some(&used),
        )
        .await?;
        let left = build_kaigi_release_authorization_v1(
            network_id,
            &used,
            &participant,
            1,
            KaigiAuthorizationActionV1::Leave,
        );
        ensure!(
            left.commitment == joined.commitment && left.nullifier != joined.nullifier,
            "leave changed opening or lost action separation"
        );
        applied(
            &clients,
            &member,
            "leave",
            vec![left.leave(call.id(), &participant).into()],
        )
        .await?;
        let departed = identical_records(&clients, call.id(), None).await?.unwrap();
        ensure!(
            departed.roster_commitments.is_empty()
                && departed.roster_root() == initial.roster_root()
                && departed.nullifier_log.len() == 3
                && departed.private_participation.entries()[0].sequence() == 2
                && departed.private_participation.entries()[0]
                    .active_commitment()
                    .is_none(),
            "leave failed to preserve retired sequence"
        );
        restart_persisted(&network, &clients, call.id(), &departed, "departed-restart").await?;
        rejected_unchanged(
            &clients,
            &host,
            &member,
            call.id(),
            "replayed-old-join-after-restart",
            joined.join(call.id(), &participant).into(),
            "nullifier already used",
            Some(&departed),
        )
        .await?;
        let rejoined = build_kaigi_release_authorization_v1(
            network_id,
            &departed,
            &participant,
            2,
            KaigiAuthorizationActionV1::Join,
        );
        ensure!(
            rejoined.commitment != joined.commitment && rejoined.nullifier != joined.nullifier,
            "rejoin reused first sequence opening"
        );
        applied(
            &clients,
            &member,
            "rejoin",
            vec![rejoined.join(call.id(), &participant).into()],
        )
        .await?;
        let reactivated = identical_records(&clients, call.id(), None).await?.unwrap();
        ensure!(
            reactivated.private_participation.entries()[0].sequence() == 2
                && reactivated.roster_commitments == vec![rejoined.commitment.clone()]
                && reactivated.nullifier_log.len() == 4,
            "rejoin state differs"
        );
        let ended = build_kaigi_release_authorization_v1(
            network_id,
            &reactivated,
            &ALICE_ID,
            0,
            KaigiAuthorizationActionV1::HostEnd,
        );
        ensure!(
            ended.commitment == created.commitment,
            "termination changed host opening"
        );
        applied(&clients, &host, "end", vec![ended.end(call.id()).into()]).await?;
        let terminal = identical_records(&clients, call.id(), None).await?.unwrap();
        ensure!(
            terminal.status == KaigiStatus::Ended
                && terminal.nullifier_log.len() == 5
                && terminal.segments_recorded == 1
                && terminal.total_billed_gas == 345
                && terminal.total_duration_ms == 1200,
            "termination lost private lifecycle"
        );
        ensure!(
            terminal.private_participation.entries()[0].original_account() == &participant
                && terminal.participants.is_empty(),
            "terminal identity or privacy projection differs"
        );
        restart_persisted(&network, &clients, call.id(), &terminal, "terminal-restart").await?;
        rejected_unchanged(
            &clients,
            &host,
            &host,
            call.id(),
            "replayed-end",
            ended.end(call.id()).into(),
            "Kaigi already ended",
            Some(&terminal),
        )
        .await?;
        rejected_unchanged(
            &clients,
            &host,
            &host,
            call.id(),
            "recreated-call",
            created.create(call.clone()).into(),
            "Kaigi already exists",
            Some(&terminal),
        )
        .await?;
        wait_for_transaction_on_peers(
            &clients,
            &create_tx,
            "original Create survives both restarts",
            CONVERGENCE_TIMEOUT,
        )
        .await?;
        common_commit(&clients).await?;
        // Hash the canonical Json metadata frame used by the ledger record owner.
        eprintln!(
            "KAIGI_PRIVACY_FOUR_VALIDATOR_V1:{TEST_NAME}:passed canonical_record_hash={}",
            iroha_crypto::Hash::new(norito::encode_canonical(&Json::try_new(&terminal)?)?)
        );
        Ok(())
    }
    .await;
    network.shutdown_and_release().await;
    result
}

#[test]
fn kaigi_rejection_control_requires_exact_native_reason() {
    let rejected = TransactionRejectionReason::Validation(ValidationFail::InstructionFailed(
        InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
            "nullifier already used".into(),
        )),
    ));
    require_native_rejection(Err(eyre!(rejected.clone())), "nullifier already used").unwrap();
    assert!(require_native_rejection(Err(eyre!(rejected)), "other reason").is_err());
    assert!(
        require_native_rejection(
            Err(eyre!("transport: nullifier already used")),
            "nullifier already used"
        )
        .is_err()
    );
    assert!(
        require_native_rejection(
            Err(eyre!(TransactionRejectionReason::Validation(
                ValidationFail::NotPermitted("nullifier already used".into())
            ))),
            "nullifier already used"
        )
        .is_err()
    );
}

#[test]
fn kaigi_proof_corruption_preserves_framing_and_public_instances() -> Result<()> {
    use iroha_data_model::zk::{BackendTag, NativePipaRProofV1, OpenVerifyEnvelope};
    let carrier = NativePipaRProofV1 {
        public_inputs: vec![[7; 32], [9; 32]],
        proof: vec![1, 2, 3, 4],
    };
    let original = OpenVerifyEnvelope {
        backend: BackendTag::NativePipaRPasta,
        circuit_id: "fixture".into(),
        vk_hash: iroha_crypto::Hash::new(b"fixture").into(),
        public_inputs: vec![10, 11],
        proof_bytes: norito::encode_canonical(&carrier)?,
        aux: Vec::new(),
    };
    let bytes = norito::encode_canonical(&original)?;
    let changed: OpenVerifyEnvelope = norito::decode_canonical(&corrupt_native_proof(&bytes)?)?;
    let mut expected_carrier = carrier.clone();
    expected_carrier.proof[2] ^= 1;
    let mut expected = original.clone();
    expected.proof_bytes = norito::encode_canonical(&expected_carrier)?;
    assert_eq!(changed, expected);
    assert_eq!(bytes.len(), norito::encode_canonical(&changed)?.len());
    let canonical_carrier = norito::encode_canonical(&carrier)?;
    let empty_proof = NativePipaRProofV1 {
        proof: Vec::new(),
        ..carrier
    };
    for bad_carrier in [
        b"ZK1\0PROF".to_vec(),
        canonical_carrier[..canonical_carrier.len() - 1].to_vec(),
        [canonical_carrier.as_slice(), &[0]].concat(),
        norito::encode_canonical(&empty_proof)?,
    ] {
        let mut bad = original.clone();
        bad.proof_bytes = bad_carrier;
        assert!(corrupt_native_proof(&norito::encode_canonical(&bad)?).is_err());
    }
    let mut wrong_engine = original;
    wrong_engine.backend = BackendTag::Stark;
    assert!(corrupt_native_proof(&norito::encode_canonical(&wrong_engine)?).is_err());
    Ok(())
}
