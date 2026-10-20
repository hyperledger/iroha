//! Four validators agree on the committed resource policy of task X.2.
//!
//! Every governance proposal that would make the transaction cap, the block payload limit and
//! the privacy byte budgets incoherent, or exceed the chain transport limit, is committed as a
//! rejected transaction with the same full result on every validator, and leaves every
//! parameter unchanged. The exact coherent boundary is accepted in either instruction order. A
//! signed transaction of exactly the 10,485,760-byte cap commits under the tightest coherent
//! block limit and the first excess byte is refused by every validator before admission.
//! Protocol byte caps remain unchanged. Signed genesis separately budgets the synthetic `Log` fixture's
//! one-gas-per-message-byte execution, plus 1,024 gas for small accompanying fixture work;
//! the ordinary 4,000,000-gas fallback would correctly reject a 10 MiB `Log`.
//! Full transaction-details checks separately fund a finite 16 MiB HTTP query source
//! phase; this changes neither default query policy nor any committed byte/gas cap.
//! Validators restart onto the same policy. A validator refuses to start with a local sync budget
//! below the committed payload plus `FRAME_OVERHEAD`, a block-sync topic cap below the P2P frame of
//! its largest sync response, or a control topic cap below the longest consensus control frame
//! (`specs/zk_resource_contract.json`).

use std::{
    borrow::Cow,
    num::NonZeroU32,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use eyre::{Result, WrapErr as _, ensure, eyre};
use integration_tests::sandbox;
use iroha::{
    blocking::Client,
    client::TransactionWaitOptions,
    data_model::{
        Level,
        asset::{AssetBalancePolicy, AssetDefinition, AssetDefinitionId, AssetId},
        isi::{
            Grant, InstructionBox, Log, Mint, Register, SetParameter,
            privacy::SchedulePrivacyConsensusPolicyTighteningV1,
        },
        parameter::{
            CustomParameter, CustomParameterId, Parameter, Parameters, TransactionParameter,
            system::{BLOCK_PAYLOAD_NON_TRANSACTION_RESERVE_BYTES, SumeragiParameter},
        },
        permission::Permission,
        privacy::PrivacyConsensusLimitsV1,
        query::{CommittedTransaction, error::QueryExecutionFail},
        transaction::{
            FeeChargeKind, FeeChargeLimit, FeePaymentIntent, SignedTransaction, TransactionBuilder,
        },
    },
};
use iroha::{data_model::ValidationFail, query::QueryError};
use iroha_config_base::toml::WriteExt as _;
use iroha_executor_data_model::permission::governance::CanEnactGovernance;
use iroha_primitives::{json::Json, numeric::Quantity};
use iroha_sumeragi::pacemaker::FRAME_OVERHEAD;
use iroha_test_network::{Network, NetworkBuilder, NetworkPeer};
use iroha_test_samples::ALICE_ID;
use toml::Table;

/// The fixed signed-transaction cap of the first release.
const TRANSACTION_CAP: u64 = 10_485_760;
/// Finite signed gas allowance for the byte-boundary `Log` and small fixture traffic.
const FIXTURE_BLOCK_GAS: u64 = TRANSACTION_CAP + 1_024;
/// The committed 16 MiB block payload default.
const BLOCK_PAYLOAD_DEFAULT: u32 = 16_777_216;
/// Complete local HTTP query reservation for a 16 MiB full-carrier source phase.
const FIXTURE_QUERY_WORKING_SET_BYTES: u64 =
    iroha_config::parameters::defaults::torii::QUERY_FANOUT_FIXED_OVERHEAD_BYTES_V1
        + iroha_config::parameters::defaults::torii::QUERY_FANOUT_PREBODY_UNITS_V1
            * BLOCK_PAYLOAD_DEFAULT as u64;
/// The tightest coherent block payload for the fixed transaction cap.
const TIGHT_BLOCK_PAYLOAD: u32 = 10_551_296;
/// An intermediate coherent block payload for the first tightening.
const MIDDLE_BLOCK_PAYLOAD: u32 = 12_582_912;
const CASE_TIMEOUT: Duration = Duration::from_secs(1_800);
const POLL: Duration = Duration::from_millis(250);
const SIZING_SLACK: usize = 8_192;

fn fee_asset() -> AssetDefinitionId {
    AssetDefinitionId::parse_address_literal(
        &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
    )
    .unwrap()
}

fn fees() -> FeePaymentIntent {
    FeePaymentIntent::authority(
        vec![FeeChargeLimit::new(
            FeeChargeKind::Nexus,
            fee_asset(),
            Quantity::one(),
        )],
        None,
    )
}

fn builder() -> NetworkBuilder {
    let mut policy = iroha_config::parameters::defaults::nexus::fees::genesis_policy();
    policy.fee_asset_id = fee_asset();
    policy.fee_sink_account_id = ALICE_ID.clone();
    policy.base_fee = 1_u32.into();
    policy.per_byte_fee = 0_u32.into();
    policy.per_instruction_fee = 0_u32.into();
    policy.per_gas_unit_fee = 0_u32.into();
    NetworkBuilder::new()
        .with_peers(4)
        .with_permissioned_consensus()
        .with_auto_populated_trusted_peers()
        .with_base_seed("x2-resource-policy-agreement-v1")
        .with_config_layer(|layer| {
            // Header agreement uses full transaction details, whose carrier is larger
            // than the default 2,562,555-byte query source phase. Fund that read
            // explicitly; status still uses its bounded committed-outcome reader.
            layer.write(
                ["torii", "query_fanout_max_working_set_bytes"],
                i64::try_from(FIXTURE_QUERY_WORKING_SET_BYTES)
                    .expect("finite fixture query working set fits configuration"),
            );
            layer.write(
                ["nexus", "storage", "local_budget_bytes"],
                1024_i64 * 1024 * 1024,
            );
        })
        .with_genesis_instruction(SetParameter::new(Parameter::Custom(
            policy.into_custom_parameter().unwrap(),
        )))
        .with_genesis_instruction(SetParameter::new(Parameter::Custom(CustomParameter::new(
            "ivm_gas_limit_per_block".parse().unwrap(),
            Json::new(FIXTURE_BLOCK_GAS),
        ))))
        .with_genesis_instruction(Register::asset_definition(AssetDefinition::numeric(
            fee_asset(),
            "Resource policy fee asset",
            AssetBalancePolicy::Global,
            None,
        )))
        .with_genesis_instruction(Mint::asset_quantity(
            1_000_u32,
            AssetId::of(fee_asset(), ALICE_ID.clone()),
        ))
        .with_genesis_instruction(Grant::account_permission(
            Permission::from(CanEnactGovernance),
            ALICE_ID.clone(),
        ))
}

fn now() -> Result<Duration> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .wrap_err("system clock is before the Unix epoch")
}

/// Sign `instructions` as Alice with a unique nonce so equal bodies have distinct hashes.
fn signed(
    client: &Client,
    instructions: Vec<InstructionBox>,
    nonce: u32,
) -> Result<SignedTransaction> {
    let mut builder = TransactionBuilder::new(
        *client.client().network_id(),
        client.client().account().clone(),
        fees(),
    )
    .with_instructions(instructions);
    builder.set_creation_time(now()?);
    builder.set_nonce(NonZeroU32::new(nonce).ok_or_else(|| eyre!("zero nonce"))?);
    builder
        .try_sign(client.client().key_pair().private_key())
        .wrap_err("sign resource policy transaction")
}

/// A signed `Log` transaction whose canonical frame (the admission measure) is `target` bytes.
fn sized_log(client: &Client, target: usize, nonce: u32) -> Result<SignedTransaction> {
    let log = |length: usize| -> Result<SignedTransaction> {
        signed(
            client,
            vec![InstructionBox::from(Log::new(
                Level::INFO,
                "x".repeat(length),
            ))],
            nonce,
        )
    };
    let frame = |transaction: &SignedTransaction| -> Result<usize> {
        Ok(norito::encode_canonical(transaction)?.len())
    };
    // Both probes stay in the same compact length band, so the frame is linear in the text.
    let initial = target
        .checked_sub(SIZING_SLACK)
        .ok_or_else(|| eyre!("target below the sizing slack"))?;
    let measured = frame(&log(initial)?)?;
    let growth = target
        .checked_sub(measured)
        .ok_or_else(|| eyre!("fixture overhead exceeds the sizing slack"))?;
    let transaction = log(initial + growth)?;
    ensure!(
        frame(&transaction)? == target,
        "canonical Log text is not byte-linear"
    );
    Ok(transaction)
}

fn deadline_left(deadline: Instant) -> Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
        .ok_or_else(|| eyre!("resource policy case exceeded its deadline"))
}

/// The exact committed transaction on one validator, by entrypoint hash, through the
/// authenticated transaction-details route (Torii admits no signed `FindTransactions` scan).
/// The route selects the one committed entrypoint by exact equality; absence means not yet
/// committed.
fn committed(
    client: &Client,
    transaction: &SignedTransaction,
) -> Result<Option<CommittedTransaction>> {
    let expected = transaction.hash_as_entrypoint();
    match client.client().get_transaction_details(expected) {
        Ok(details) => {
            ensure!(
                details.transaction.entrypoint_hash() == &expected,
                "the details route returned another entrypoint"
            );
            Ok(Some(details.transaction))
        }
        Err(QueryError::Validation(ValidationFail::QueryFailed(QueryExecutionFail::NotFound))) => {
            Ok(None)
        }
        Err(error) => Err(error).wrap_err("query the committed transaction details"),
    }
}

/// Wait until every validator has committed `transaction`; return their full records.
fn committed_on_all(
    clients: &[Client],
    transaction: &SignedTransaction,
    deadline: Instant,
) -> Result<Vec<CommittedTransaction>> {
    loop {
        let mut records = Vec::with_capacity(clients.len());
        for client in clients {
            if let Some(record) = committed(client, transaction)? {
                records.push(record);
            }
        }
        if records.len() == clients.len() {
            return Ok(records);
        }
        deadline_left(deadline).wrap_err("a validator did not commit the transaction")?;
        std::thread::sleep(POLL);
    }
}

/// Every validator committed the same block and the same full result for `transaction`.
fn identical_result(records: &[CommittedTransaction]) -> Result<&CommittedTransaction> {
    let first = records
        .first()
        .ok_or_else(|| eyre!("no validator record"))?;
    for (index, record) in records.iter().enumerate() {
        ensure!(
            record.block_hash() == first.block_hash()
                && record.result() == first.result()
                && record.result().hash() == first.result().hash(),
            "validator {index} committed {:?} in {}, validator 0 {:?} in {}",
            record.result(),
            record.block_hash(),
            first.result(),
            first.block_hash()
        );
    }
    Ok(first)
}

fn parameters_on_all(clients: &[Client]) -> Result<Parameters> {
    let first = clients[0].client().get_parameters()?;
    for (index, client) in clients.iter().enumerate().skip(1) {
        ensure!(
            client.client().get_parameters()? == first,
            "validator {index} reports different committed parameters"
        );
    }
    Ok(first)
}

fn privacy_limits_on_all(clients: &[Client]) -> Result<PrivacyConsensusLimitsV1> {
    let policy = |client: &Client| -> Result<_> {
        Ok(client.client().get_privacy_capabilities()?.consensus_policy)
    };
    let first = policy(&clients[0])?;
    for (index, client) in clients.iter().enumerate().skip(1) {
        ensure!(
            policy(client)? == first,
            "validator {index} reports a different privacy policy"
        );
    }
    ensure!(
        first.pending_tightening.is_none(),
        "a privacy tightening is still pending: {first:?}"
    );
    Ok(first.current_limits)
}

/// A proposal that would make the committed policy incoherent: rejected identically by every
/// validator, with every parameter and the privacy policy unchanged.
fn assert_identically_rejected(
    clients: &[Client],
    transaction: &SignedTransaction,
    expected: &str,
    deadline: Instant,
) -> Result<()> {
    let parameters = parameters_on_all(clients)?;
    let privacy = privacy_limits_on_all(clients)?;
    clients[0]
        .submit_transaction(transaction)
        .wrap_err("Torii admits the signed proposal")?;
    let records = committed_on_all(clients, transaction, deadline)?;
    let record = identical_result(&records)?;
    let rendered = format!("{:?}", record.result());
    ensure!(
        record.result().0.is_err() && rendered.contains(expected),
        "expected a rejection containing {expected:?}, got {rendered}"
    );
    ensure!(
        parameters_on_all(clients)? == parameters,
        "parameters changed"
    );
    ensure!(
        privacy_limits_on_all(clients)? == privacy,
        "privacy policy changed"
    );
    Ok(())
}

/// A coherent proposal: applied identically by every validator.
fn assert_identically_applied(
    clients: &[Client],
    transaction: &SignedTransaction,
    deadline: Instant,
) -> Result<()> {
    clients[0]
        .submit_transaction(transaction)
        .wrap_err("Torii admits the signed proposal")?;
    let records = committed_on_all(clients, transaction, deadline)?;
    let record = identical_result(&records)?;
    ensure!(
        record.result().0.is_ok(),
        "expected the coherent proposal to apply, got {:?}",
        record.result()
    );
    Ok(())
}

/// Distinct transaction nonces, so equal instruction lists have distinct hashes.
struct Nonces(u32);

impl Nonces {
    fn next(&mut self) -> u32 {
        self.0 += 1;
        self.0
    }
}

fn status_height(rt: &tokio::runtime::Runtime, peer: &NetworkPeer) -> Result<u64> {
    Ok(rt.block_on(peer.status())?.blocks)
}

/// Wait until every validator has applied `height`; an idle chain creates no blocks, so commit
/// small `Log` transactions only while no validator has reached it yet. Returns the last filler
/// committed here, if any.
fn advance_to(
    rt: &tokio::runtime::Runtime,
    network: &Network,
    clients: &[Client],
    height: u64,
    nonces: &mut Nonces,
    deadline: Instant,
) -> Result<Option<SignedTransaction>> {
    let mut last = None;
    loop {
        // A restarting validator may briefly not answer; the case deadline bounds the wait.
        let heights: Vec<u64> = network
            .validators()
            .iter()
            .map(|peer| status_height(rt, peer).unwrap_or(0))
            .collect();
        if heights.iter().all(|applied| *applied >= height) {
            return Ok(last);
        }
        deadline_left(deadline).wrap_err_with(|| format!("heights {heights:?} below {height}"))?;
        if heights.iter().all(|applied| *applied < height) {
            let nonce = nonces.next();
            let filler = signed(
                &clients[0],
                vec![InstructionBox::from(Log::new(
                    Level::INFO,
                    format!("advance {nonce}"),
                ))],
                nonce,
            )?;
            clients[0]
                .submit_transaction_and_wait(&filler)
                .wrap_err("commit a filler block")?;
            last = Some(filler);
        } else {
            std::thread::sleep(POLL);
        }
    }
}

/// Every validator holds the same committed tip block at `height`, hence through the parent-hash
/// chain the same header at every height up to it. Each validator itself reports that its
/// committed height is exactly `height`, that `anchor` is committed in block `height` (local
/// pipeline status) and that block's hash (transaction-details route). Height zero, a validator
/// below or above `height`, one without `anchor`, or one with another tip hash fails.
fn headers_agree(
    rt: &tokio::runtime::Runtime,
    network: &Network,
    clients: &[Client],
    height: u64,
    anchor: &SignedTransaction,
) -> Result<()> {
    ensure!(height > 0, "header agreement needs a committed height");
    ensure!(
        !clients.is_empty() && network.validators().len() == clients.len(),
        "one client per validator"
    );
    let mut records = Vec::with_capacity(clients.len());
    for (index, (peer, client)) in network.validators().iter().zip(clients).enumerate() {
        let reached = status_height(rt, peer)?;
        ensure!(
            reached == height,
            "validator {index} is at height {reached}, not {height}"
        );
        let status = client
            .client()
            .get_transaction_status_response_local(anchor.hash())
            .wrap_err("read the anchor's local pipeline status")?
            .ok_or_else(|| eyre!("validator {index} reports no status for the anchor"))?;
        ensure!(
            matches!(status.status.kind.as_str(), "Committed" | "Applied")
                && status.status.block_height == Some(height),
            "validator {index} reports the anchor as {:?}, not committed in block {height}",
            status.status
        );
        records.push(
            committed(client, anchor)?
                .ok_or_else(|| eyre!("validator {index} has not committed the anchor"))?,
        );
    }
    let first = &records[0];
    for (index, record) in records.iter().enumerate().skip(1) {
        ensure!(
            record.block_hash() == first.block_hash(),
            "validator {index} holds tip {} at height {height}, validator 0 {}",
            record.block_hash(),
            first.block_hash()
        );
    }
    Ok(())
}

/// The first excess byte is a permanent signed-size refusal before admission.
async fn refuse_one_over_http(
    peer: &NetworkPeer,
    transaction: &SignedTransaction,
    deadline: Instant,
) -> Result<()> {
    let frame = norito::encode_canonical(transaction)?.len();
    ensure!(u64::try_from(frame)? == TRANSACTION_CAP + 1);
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let response = tokio::time::timeout_at(
        tokio::time::Instant::from_std(deadline),
        client
            .post(format!("{}/v1/pipeline/transactions", peer.torii_url()))
            .header("Content-Type", "application/x-norito")
            .header("Accept", "application/x-norito")
            .body(transaction.encode_wire_v1()?)
            .send(),
    )
    .await??;
    ensure!(
        response.status() == reqwest::StatusCode::BAD_REQUEST,
        "first excess byte must be a permanent admission refusal, got {}",
        response.status()
    );
    ensure!(
        response
            .headers()
            .get("x-iroha-reject-code")
            .is_some_and(|value| value == "transaction_rejected")
    );
    let body = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), response.bytes())
        .await??;
    let envelope: iroha_torii_shared::ErrorEnvelope = norito::decode_canonical(&body)?;
    let expected = format!(
        "failed to accept transaction: Transaction size {} bytes exceeds limit {} bytes",
        TRANSACTION_CAP + 1,
        TRANSACTION_CAP
    );
    ensure!(
        format!("{envelope:?}").contains(&expected),
        "unexpected refusal envelope {envelope:?}"
    );
    Ok(())
}

/// Start the stopped `peer` with `layer` over its configuration and require the daemon to refuse
/// to start, naming the refused setting in its output or startup error.
fn refused_at_startup(
    rt: &tokio::runtime::Runtime,
    network: &Network,
    peer: &NetworkPeer,
    layer: Table,
    names: &[&str],
) -> Result<()> {
    let layers: Vec<Cow<'_, Table>> = network
        .config_layers_for_peer(peer)
        .chain(std::iter::once(Cow::Owned(layer)))
        .collect();
    let started = rt.block_on(async {
        tokio::time::timeout(
            network.peer_startup_timeout(),
            peer.start_checked(layers.iter(), None),
        )
        .await
    });
    let stopped = Instant::now() + Duration::from_secs(60);
    while peer.is_running() && Instant::now() < stopped {
        std::thread::sleep(POLL);
    }
    ensure!(
        !peer.is_running(),
        "a validator configured past {names:?} kept running: {started:?}"
    );
    let mut logs = String::new();
    for path in [peer.latest_stderr_log_path(), peer.latest_stdout_log_path()]
        .into_iter()
        .flatten()
    {
        logs.push_str(&std::fs::read_to_string(path).unwrap_or_default());
    }
    let started = format!("{started:?}");
    ensure!(
        names
            .iter()
            .any(|name| logs.contains(name) || started.contains(name)),
        "the startup refusal must name {names:?}: {started}"
    );
    Ok(())
}

fn sumeragi(parameter: SumeragiParameter) -> InstructionBox {
    SetParameter::new(Parameter::Sumeragi(parameter)).into()
}

fn block_bytes(bytes: u32) -> InstructionBox {
    sumeragi(SumeragiParameter::MaxBlockBytes(
        std::num::NonZeroU32::new(bytes).expect("nonzero block payload"),
    ))
}

fn tighten(effective_at_height: u64, limits: PrivacyConsensusLimitsV1) -> InstructionBox {
    SchedulePrivacyConsensusPolicyTighteningV1::new(effective_at_height, limits).into()
}

#[test]
#[ignore = "four validators, 10 MiB transactions and all-node restart; same-source daemon required"]
#[allow(clippy::too_many_lines)]
fn four_validators_agree_on_resource_policy_bounds_and_coherence() -> Result<()> {
    let (network, rt) = sandbox::start_network_blocking_or_skip(
        builder(),
        stringify!(four_validators_agree_on_resource_policy_bounds_and_coherence),
    )?
    .ok_or_else(|| eyre!("the four-validator resource policy network must not skip"))?;
    let deadline = Instant::now() + CASE_TIMEOUT;
    let result = (|| -> Result<()> {
        ensure!(network.validators().len() == 4);
        let clients: Vec<Client> = network
            .validators()
            .iter()
            .map(|peer| peer.client().with_request_deadline(deadline))
            .collect::<Result<_, _>>()?;
        let mut nonces = Nonces(1);

        // Committed defaults, identical on every validator.
        let defaults = parameters_on_all(&clients)?;
        let gas_parameter = defaults
            .custom()
            .get(&"ivm_gas_limit_per_block".parse::<CustomParameterId>()?)
            .ok_or_else(|| eyre!("the signed fixture gas allowance is absent"))?;
        ensure!(
            gas_parameter.payload().try_into_any_norito::<u64>()? == FIXTURE_BLOCK_GAS,
            "validators must execute the finite signed fixture gas allowance"
        );
        ensure!(defaults.transaction().max_tx_bytes().get() == TRANSACTION_CAP);
        ensure!(defaults.sumeragi().max_block_bytes().get() == BLOCK_PAYLOAD_DEFAULT);
        let reserve = BLOCK_PAYLOAD_NON_TRANSACTION_RESERVE_BYTES;
        let privacy = privacy_limits_on_all(&clients)?;
        ensure!(privacy == PrivacyConsensusLimitsV1::taira_default());
        ensure!(privacy.max_privacy_bytes_per_block + reserve == BLOCK_PAYLOAD_DEFAULT);

        // Incoherent proposals: one byte beyond each committed relation.
        let cases: [(InstructionBox, String); 4] = [
            (
                SetParameter::new(Parameter::Transaction(TransactionParameter::MaxTxBytes(
                    std::num::NonZeroU64::new(u64::from(BLOCK_PAYLOAD_DEFAULT - reserve + 1))
                        .unwrap(),
                )))
                .into(),
                format!(
                    "transaction cap {} plus block reserve {reserve} requires {} bytes, \
                     exceeding block cap {BLOCK_PAYLOAD_DEFAULT}",
                    BLOCK_PAYLOAD_DEFAULT - reserve + 1,
                    u64::from(BLOCK_PAYLOAD_DEFAULT) + 1
                ),
            ),
            (
                block_bytes(BLOCK_PAYLOAD_DEFAULT + 1),
                "MaxBlockBytesAboveTransport".to_owned(),
            ),
            (
                block_bytes(TIGHT_BLOCK_PAYLOAD - 1),
                format!(
                    "transaction cap {TRANSACTION_CAP} plus block reserve {reserve} requires \
                     {TIGHT_BLOCK_PAYLOAD} bytes, exceeding block cap {}",
                    TIGHT_BLOCK_PAYLOAD - 1
                ),
            ),
            (
                block_bytes(TIGHT_BLOCK_PAYLOAD),
                format!(
                    "privacy block budget {} plus block reserve {reserve} requires \
                     {BLOCK_PAYLOAD_DEFAULT} bytes, exceeding block cap {TIGHT_BLOCK_PAYLOAD}",
                    privacy.max_privacy_bytes_per_block
                ),
            ),
        ];
        for (instruction, expected) in cases {
            let proposal = signed(&clients[0], vec![instruction], nonces.next())?;
            assert_identically_rejected(&clients, &proposal, &expected, deadline)?;
        }

        // Exact coherent boundaries, in both instruction orders. The tightening becomes
        // effective with the lag-two block limit, never after it.
        let middle = PrivacyConsensusLimitsV1 {
            max_privacy_bytes_per_block: MIDDLE_BLOCK_PAYLOAD - reserve,
            ..privacy
        };
        let height = status_height(&rt, &network.validators()[0])?;
        let first = signed(
            &clients[0],
            vec![
                block_bytes(MIDDLE_BLOCK_PAYLOAD),
                tighten(height + 3, middle),
            ],
            nonces.next(),
        )?;
        assert_identically_applied(&clients, &first, deadline)?;
        advance_to(&rt, &network, &clients, height + 4, &mut nonces, deadline)?;
        ensure!(
            parameters_on_all(&clients)?
                .sumeragi()
                .max_block_bytes()
                .get()
                == MIDDLE_BLOCK_PAYLOAD
        );
        ensure!(privacy_limits_on_all(&clients)? == middle);

        let tight = PrivacyConsensusLimitsV1 {
            max_privacy_bytes_per_block: TIGHT_BLOCK_PAYLOAD - reserve,
            ..middle
        };
        ensure!(u64::from(tight.max_privacy_bytes_per_block) == TRANSACTION_CAP);
        let height = status_height(&rt, &network.validators()[0])?;
        let second = signed(
            &clients[0],
            vec![tighten(height + 3, tight), block_bytes(TIGHT_BLOCK_PAYLOAD)],
            nonces.next(),
        )?;
        assert_identically_applied(&clients, &second, deadline)?;
        advance_to(&rt, &network, &clients, height + 4, &mut nonces, deadline)?;
        let tightened = parameters_on_all(&clients)?;
        ensure!(tightened.sumeragi().max_block_bytes().get() == TIGHT_BLOCK_PAYLOAD);
        ensure!(tightened.transaction().max_tx_bytes().get() == TRANSACTION_CAP);
        ensure!(privacy_limits_on_all(&clients)? == tight);

        // Under the tightest block limit, one more transaction byte is incoherent.
        let over_cap = signed(
            &clients[0],
            vec![
                SetParameter::new(Parameter::Transaction(TransactionParameter::MaxTxBytes(
                    std::num::NonZeroU64::new(TRANSACTION_CAP + 1).unwrap(),
                )))
                .into(),
            ],
            nonces.next(),
        )?;
        assert_identically_rejected(
            &clients,
            &over_cap,
            &format!(
                "transaction cap {} plus block reserve {reserve} requires {} bytes, exceeding \
                 block cap {TIGHT_BLOCK_PAYLOAD}",
                TRANSACTION_CAP + 1,
                u64::from(TIGHT_BLOCK_PAYLOAD) + 1
            ),
            deadline,
        )?;

        // Exact signed-transaction cap: committed by every validator in the tightest block.
        let cap = usize::try_from(TRANSACTION_CAP)?;
        let exact = sized_log(&clients[0], cap, nonces.next())?;
        let hash = clients[0]
            .submit_transaction_and_wait(&exact)
            .wrap_err("the exact cap commits")?;
        for (index, client) in clients.iter().enumerate() {
            client
                .wait_for_transaction_applied_local(
                    hash,
                    TransactionWaitOptions {
                        timeout: deadline_left(deadline)?,
                        poll_interval: POLL,
                    },
                )
                .wrap_err_with(|| format!("validator {index} applies the exact cap"))?;
        }
        // The first excess byte is refused by every validator before admission.
        let over = sized_log(&clients[0], cap + 1, nonces.next())?;
        for peer in network.validators() {
            rt.block_on(refuse_one_over_http(peer, &over, deadline))?;
        }
        let tip = status_height(&rt, &network.validators()[0])?;
        advance_to(&rt, &network, &clients, tip, &mut nonces, deadline)?;
        // The exact cap's block is the committed tip on every validator.
        headers_agree(&rt, &network, &clients, tip, &exact)?;

        // All validators restart onto the same committed policy and continue.
        rt.block_on(network.shutdown());
        rt.block_on(network.start_all())?;
        advance_to(&rt, &network, &clients, tip, &mut nonces, deadline)?;
        ensure!(parameters_on_all(&clients)? == tightened);
        ensure!(privacy_limits_on_all(&clients)? == tight);
        let filler = advance_to(&rt, &network, &clients, tip + 1, &mut nonces, deadline)?
            .ok_or_else(|| eyre!("height {} was reached without a committed filler", tip + 1))?;
        headers_agree(&rt, &network, &clients, tip + 1, &filler)?;

        // A local sync budget one byte below the committed payload plus FRAME_OVERHEAD.
        let peer = &network.validators()[3];
        rt.block_on(peer.shutdown());
        let short = TIGHT_BLOCK_PAYLOAD + FRAME_OVERHEAD - 1;
        refused_at_startup(
            &rt,
            &network,
            peer,
            Table::new().write(["sumeragi", "sync_max_bytes"], i64::from(short)),
            &["SyncMaxBytesTooSmall"],
        )?;
        // Topic caps one byte below the complete P2P frame of the node's own largest sync
        // response and of the longest consensus control frame.
        let id = peer.id();
        let block_sync = iroha_core::sumeragi::net::minimum_block_sync_frame_bytes(
            &id,
            &iroha_config::parameters::actual::SumeragiLocalOverrides::default(),
        );
        refused_at_startup(
            &rt,
            &network,
            peer,
            Table::new().write(
                ["network", "max_frame_bytes_block_sync"],
                i64::try_from(block_sync - 1)?,
            ),
            &[
                "NetworkBlockSyncFrameBelowSyncBudget",
                "cannot carry the largest sync response",
            ],
        )?;
        let control = iroha_core::sumeragi::net::minimum_control_frame_bytes(&id);
        refused_at_startup(
            &rt,
            &network,
            peer,
            Table::new().write(
                ["network", "max_frame_bytes_control"],
                i64::try_from(control - 1)?,
            ),
            &[
                "NetworkControlFrameBelowControlMaximum",
                "cannot carry the largest consensus control frame",
            ],
        )?;
        // Restarted with its default configuration, it rejoins the same chain.
        let layers: Vec<Cow<'_, Table>> = network.config_layers_for_peer(peer).collect();
        rt.block_on(peer.start_checked(layers.iter(), None))?;
        let filler = advance_to(&rt, &network, &clients, tip + 2, &mut nonces, deadline)?
            .ok_or_else(|| eyre!("height {} was reached without a committed filler", tip + 2))?;
        headers_agree(&rt, &network, &clients, tip + 2, &filler)?;
        ensure!(parameters_on_all(&clients)? == tightened);
        Ok(())
    })();
    rt.block_on(network.shutdown_and_release());
    result
}
