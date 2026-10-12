#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
//! Integration tests validating multi-signature transaction flows.
use eyre::{Result, WrapErr, eyre};
use integration_tests::{
    binary_resolver::{iroha_program, prepare_iroha_cli_test_environment},
    process::{output_with_timeout, process_timeout},
    sandbox,
};
use iroha::{
    blocking::Client,
    client::{MultisigProposalEntry, MultisigProposalsQueryRequest},
    config::DEFAULT_TRANSACTION_TIME_TO_LIVE,
    crypto::{ExposedPrivateKey, KeyPair},
    data_model::{
        Level,
        account::{MultisigMember, MultisigPolicy},
        isi::AddSignatory,
        prelude::*,
    },
    executor_data_model::isi::multisig::*,
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name::Name;
use iroha_test_network::*;
use iroha_test_samples::{
    ALICE_ID, BOB_ID, BOB_KEYPAIR, CARPENTER_ID, CARPENTER_KEYPAIR, gen_account_in,
};
use iroha_torii::{
    MultisigAccountSelectorDto, MultisigCancelRequestDto, MultisigProposalsQueryRequestDto,
    MultisigProposalsResolveRequestDto,
};
use norito::json::Value as JsonValue;
use reqwest::header::CONTENT_TYPE;
use std::{
    collections::BTreeMap,
    num::{NonZeroU16, NonZeroU64},
    path::Path,
    time::{Duration, Instant},
};
use tokio::runtime::Runtime;
const DOMAIN_REGISTRATION_RECOVERY_TIMEOUT: Duration = Duration::from_secs(60);
const DOMAIN_REGISTRATION_RECOVERY_POLL: Duration = Duration::from_millis(250);
const ACCOUNT_VISIBILITY_TIMEOUT: Duration = Duration::from_secs(30);
const ACCOUNT_VISIBILITY_POLL: Duration = Duration::from_millis(100);
const CANONICAL_EXECUTOR: &[u8] = include_bytes!("../../defaults/executor.to");
fn proposal_nonce(seed: u8) -> MultisigProposalNonce {
    MultisigProposalNonce::new([seed; 32]).expect("nonzero fixture nonce")
}
fn occurrence(
    client: &Client,
    account: &AccountId,
    nonce: MultisigProposalNonce,
) -> MultisigProposalId {
    MultisigProposalId::derive(client.client().network_id(), account, &nonce)
}
fn start_network(
    builder: NetworkBuilder,
    context: &'static str,
) -> Option<(sandbox::SerializedNetwork, Runtime)> {
    prepare_iroha_cli_test_environment();
    sandbox::start_network_blocking_or_skip(
        builder.with_peer_startup_timeout(Duration::from_secs(300)),
        context,
    )
    .unwrap()
}
fn multisig_supported(_client: &Client) -> bool {
    // Multisig instructions are carried via `CustomInstruction` envelope and are
    // executed by the core runtime path; they are not guaranteed to appear as
    // dedicated identifiers in `FindExecutorDataModel`.
    true
}
fn upgrade_executor(client: &Client) -> Result<()> {
    let bytecode = iroha::data_model::transaction::executable::IvmBytecode::from_compiled(
        CANONICAL_EXECUTOR.to_vec(),
    );
    let upgrade_executor = Upgrade::new(Executor::new(bytecode));
    client
        .submit(
            upgrade_executor,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .wrap_err("Have you set IvmFuelConfig::Auto?")?;
    Ok(())
}
fn is_inconclusive_domain_registration_error(err: &eyre::Report) -> bool {
    const NEEDLES: [&str; 4] = [
        "haven't got tx confirmation within",
        "transaction queued for too long",
        "fallback status check failed",
        "operation timed out",
    ];
    err.chain().any(|cause| {
        let text = cause.to_string();
        NEEDLES.iter().any(|needle| text.contains(needle))
    })
}
fn domain_visible(client: &Client, domain: &DomainId) -> Result<bool> {
    Ok(client
        .client()
        .query(FindDomains::new())
        .execute_all()?
        .into_iter()
        .any(|registered| registered.id() == domain))
}
fn wait_for_domain_visibility(
    client: &Client,
    domain: &DomainId,
    timeout: Duration,
) -> Result<bool> {
    let deadline = Instant::now() + timeout;
    let mut last_err = None;
    loop {
        match domain_visible(client, domain) {
            Ok(true) => return Ok(true),
            Ok(false) => {}
            Err(err) => last_err = Some(err),
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(DOMAIN_REGISTRATION_RECOVERY_POLL);
    }
    if let Some(err) = last_err {
        Err(err).wrap_err_with(|| {
            format!("timed out waiting for multisig test domain `{domain}` visibility")
        })
    } else {
        Ok(false)
    }
}
fn find_account(client: &Client, account_id: &AccountId) -> Result<Option<Account>> {
    Ok(client
        .client()
        .query(FindAccounts::new())
        .execute_all()?
        .into_iter()
        .find(|account| account.id() == account_id))
}
fn wait_for_account_visibility(
    client: &Client,
    account_id: &AccountId,
    context: &str,
) -> Result<Account> {
    let deadline = Instant::now() + ACCOUNT_VISIBILITY_TIMEOUT;
    let mut last_error = None;
    while Instant::now() < deadline {
        match find_account(client, account_id) {
            Ok(Some(account)) => return Ok(account),
            Ok(None) => {}
            Err(err) => last_error = Some(err),
        }
        std::thread::sleep(ACCOUNT_VISIBILITY_POLL);
    }
    if let Some(err) = last_error {
        Err(err).wrap_err_with(|| {
            format!("timed out waiting for account `{account_id}` visibility after {context}")
        })
    } else {
        Err(eyre!(
            "timed out waiting for account `{account_id}` visibility after {context}"
        ))
    }
}
fn wait_for_account_metadata_value(
    client: &Client,
    account_id: &AccountId,
    key: &Name,
    context: &str,
) -> Result<Json> {
    let deadline = Instant::now() + ACCOUNT_VISIBILITY_TIMEOUT;
    let mut last_error = None;
    let mut last_seen = None;
    while Instant::now() < deadline {
        match find_account(client, account_id) {
            Ok(Some(account)) => {
                if let Some(value) = account.metadata().get(key).cloned() {
                    return Ok(value);
                }
                last_seen = Some(format!("{:?}", account.metadata()));
            }
            Ok(None) => {
                last_seen = Some("account not found".to_owned());
            }
            Err(err) => last_error = Some(err),
        }
        std::thread::sleep(ACCOUNT_VISIBILITY_POLL);
    }
    if let Some(err) = last_error {
        Err(err).wrap_err_with(|| {
            format!("timed out waiting for account `{account_id}` metadata `{key}` after {context}")
        })
    } else {
        Err(eyre!(
            "timed out waiting for account `{account_id}` metadata `{key}` after {context}; last seen: {}",
            last_seen.unwrap_or_else(|| "nothing".to_owned())
        ))
    }
}
fn register_runtime_domain(network: &Network, client: &Client, domain: &DomainId) -> Result<()> {
    let register_domain =
        || submit_ensure_domain_for_network(network, client, Domain::new(domain.clone()));
    match register_domain() {
        Ok(()) => Ok(()),
        Err(err) if is_inconclusive_domain_registration_error(&err) => {
            if wait_for_domain_visibility(client, domain, DOMAIN_REGISTRATION_RECOVERY_TIMEOUT)? {
                return Ok(());
            }
            let retry = register_domain();
            match retry {
                Ok(_) => Ok(()),
                Err(retry_err)
                    if wait_for_domain_visibility(
                        client,
                        domain,
                        DOMAIN_REGISTRATION_RECOVERY_TIMEOUT,
                    )? =>
                {
                    Ok(())
                }
                Err(retry_err) => Err(retry_err),
            }
        }
        Err(err) => Err(err),
    }
    .wrap_err_with(|| format!("register multisig test domain `{domain}`"))
}
fn register_runtime_domain_and_transfer_to_bob(
    network: &Network,
    client: &Client,
    domain: &DomainId,
) -> Result<()> {
    register_runtime_domain(network, client, domain)?;
    client
        .submit(
            Transfer::domain(ALICE_ID.clone(), domain.clone(), BOB_ID.clone()),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .wrap_err_with(|| format!("transfer multisig test domain `{domain}` to bob"))?;
    Ok(())
}
fn canonical_multisig_account_id(spec: &MultisigSpec) -> AccountId {
    let members = spec
        .signatories
        .iter()
        .map(|(account, weight)| {
            let signatory = account
                .controller()
                .single_signatory()
                .expect("multisig signatories must remain single-key accounts");
            MultisigMember::new(signatory.clone(), u16::from(*weight))
                .expect("multisig member should derive from valid spec")
        })
        .collect();
    let policy =
        MultisigPolicy::new(spec.quorum.get(), members).expect("multisig policy should derive");
    AccountId::new_multisig(policy)
}
fn post_torii_app_json<T: norito::json::JsonSerialize + ?Sized>(
    rt: &Runtime,
    endpoint: &str,
    body: &T,
) -> Result<JsonValue> {
    let payload = norito::json::to_vec(body)?;
    let response_body = rt.block_on(async {
        let response = integration_tests::http::client()
            .post(endpoint)
            .header(CONTENT_TYPE, "application/json")
            .body(payload)
            .send()
            .await?;
        let status = response.status();
        let body = response.text().await?;
        if !status.is_success() {
            return Err(eyre!(
                "HTTP status {status} for `{endpoint}` with body: {body}"
            ));
        }
        Ok(body)
    })?;
    norito::json::from_str(&response_body).map_err(Into::into)
}
fn wait_for_multisig_proposal_status(
    rt: &Runtime,
    torii_base: &str,
    selector: &MultisigAccountSelectorDto,
    proposal_id: &str,
    expected_status: &str,
) -> Result<JsonValue> {
    let endpoint = format!("{torii_base}/v1/multisig/proposals/resolve");
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut last_status = None;
    let mut last_error = None;
    while Instant::now() < deadline {
        match post_torii_app_json(
            rt,
            &endpoint,
            &MultisigProposalsResolveRequestDto {
                selector: selector.clone(),
                proposal_id: proposal_id.parse()?,
            },
        ) {
            Ok(payload) => {
                let status = payload
                    .get("status")
                    .and_then(JsonValue::as_str)
                    .map(ToOwned::to_owned);
                if status.as_deref() == Some(expected_status) {
                    return Ok(payload);
                }
                last_status = status;
                last_error = None;
            }
            Err(err) => last_error = Some(err),
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    if let Some(status) = last_status {
        Err(eyre!(
            "timed out waiting for multisig proposal `{proposal_id}` status `{expected_status}`; last status `{status}`"
        ))
    } else if let Some(err) = last_error {
        Err(err).wrap_err_with(|| {
            format!(
                "timed out waiting for multisig proposal `{proposal_id}` status `{expected_status}`"
            )
        })
    } else {
        Err(eyre!(
            "timed out waiting for multisig proposal `{proposal_id}` status `{expected_status}`"
        ))
    }
}
fn cli_envs_for_signatory(client: &Client, key_pair: &KeyPair) -> Vec<(&'static str, String)> {
    let ttl = client
        .client()
        .transaction_ttl()
        .unwrap_or(DEFAULT_TRANSACTION_TIME_TO_LIVE);
    vec![
        ("CHAIN", client.client().chain().to_string()),
        ("NETWORK_ID", client.client().network_id().to_string()),
        ("TORII_URL", client.client().endpoint().to_string()),
        (
            "ACCOUNT_CHAIN_DISCRIMINANT",
            client.client().account_chain_discriminant().to_string(),
        ),
        ("ACCOUNT_PUBLIC_KEY", key_pair.public_key().to_string()),
        (
            "ACCOUNT_PRIVATE_KEY",
            ExposedPrivateKey(key_pair.private_key().clone()).to_string(),
        ),
        (
            "TRANSACTION_STATUS_TIMEOUT_MS",
            client
                .client()
                .transaction_status_timeout()
                .as_millis()
                .to_string(),
        ),
        ("TRANSACTION_TIME_TO_LIVE_MS", ttl.as_millis().to_string()),
    ]
}
fn multisig_role_suffix(role: &RoleId) -> Option<&str> {
    role.name()
        .as_ref()
        .strip_prefix("MULTISIG_SIGNATORY/")?
        .rsplit_once('/')
        .map(|(_, suffix)| suffix)
}
const COLLECTING_SIGNATURES_STATUS: &str = "COLLECTING_SIGNATURES";
fn collect_multisig_proposals(
    client: &Client,
    multisig_account_id: &AccountId,
) -> Result<Vec<MultisigProposalEntry>> {
    let mut cursor = None;
    let mut items = Vec::new();
    loop {
        let response =
            client
                .client()
                .post_multisig_proposals_query(&MultisigProposalsQueryRequest {
                    multisig_account_id: Some(multisig_account_id.clone()),
                    multisig_account_alias: None,
                    status: vec![COLLECTING_SIGNATURES_STATUS.to_owned()],
                    cursor: cursor.clone(),
                    limit: Some(100),
                })?;
        items.extend(response.proposals);
        let Some(next_cursor) = response.next_cursor else {
            break;
        };
        cursor = Some(next_cursor);
    }
    Ok(items)
}
fn wait_for_multisig_proposals(
    client: &Client,
    multisig_account_id: &AccountId,
    minimum_count: usize,
) -> Result<Vec<MultisigProposalEntry>> {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut last_count = 0_usize;
    while Instant::now() < deadline {
        let proposals = collect_multisig_proposals(client, multisig_account_id)?;
        if proposals.len() >= minimum_count {
            return Ok(proposals);
        }
        last_count = proposals.len();
        std::thread::sleep(Duration::from_millis(250));
    }
    Err(eyre!(
        "timed out waiting for at least {minimum_count} proposals for explicit multisig selector; last count {last_count}"
    ))
}
fn run_multisig_list_all_cli(
    cli_program: &Path,
    client: &Client,
    key_pair: &KeyPair,
    multisig_selector: &str,
    extra_args: &[&str],
) -> Result<std::process::Output> {
    let cli_dir = tempfile::tempdir().wrap_err("create CLI working directory")?;
    let mut command = std::process::Command::new(cli_program);
    command
        .current_dir(cli_dir.path())
        .envs(cli_envs_for_signatory(client, key_pair));
    let mut list_args = Vec::new();
    let mut index = 0;
    while index < extra_args.len() {
        let arg = extra_args[index];
        if arg == "--output-format" {
            let value = *extra_args
                .get(index + 1)
                .ok_or_else(|| eyre!("missing value for `--output-format`"))?;
            command.arg(arg).arg(value);
            index += 2;
            continue;
        }
        if arg.starts_with("--output-format=") {
            command.arg(arg);
            index += 1;
            continue;
        }
        list_args.push(arg);
        index += 1;
    }
    command
        .arg("ledger")
        .arg("multisig")
        .arg("list")
        .arg("all")
        .arg("--multisig-selector")
        .arg(multisig_selector)
        .args(list_args);
    output_with_timeout(&mut command, process_timeout())
        .wrap_err("run `iroha ledger multisig list all`")
}
#[test]
fn multisig_normal() -> Result<()> {
    multisig_base(TestSuite::normal(), stringify!(multisig_normal))
}
#[test]
fn multisig_unauthorized() -> Result<()> {
    multisig_base(TestSuite::unauthorized(), stringify!(multisig_unauthorized))
}
#[test]
fn multisig_expires() -> Result<()> {
    multisig_base(TestSuite::expires(), stringify!(multisig_expires))
}
#[test]
fn nested_multisig_registration_is_rejected() -> Result<()> {
    multisig_recursion_base(stringify!(nested_multisig_registration_is_rejected))
}
#[test]
fn multisig_cancel_route_persists_canceled_terminal_state() -> Result<()> {
    let context = stringify!(multisig_cancel_route_persists_canceled_terminal_state);
    let builder = NetworkBuilder::new();
    let Some((network, rt)) = start_network(builder, context) else {
        return Ok(());
    };
    let test_client = network.client();
    if !multisig_supported(&test_client) {
        eprintln!("skipping {context}: executor does not support multisig");
        return Ok(());
    }
    let domain: DomainId = DomainId::try_new("multisig-cancel-terminal", "universal").unwrap();
    register_runtime_domain(&network, &test_client, &domain)
        .wrap_err("register multisig cancel test domain")?;
    let spec = MultisigSpec::new(
        BTreeMap::from([(ALICE_ID.clone(), 1), (BOB_ID.clone(), 1)]),
        NonZeroU16::new(2).unwrap(),
        NonZeroU64::new(60_000).unwrap(),
    );
    let multisig_seed_account_id = AccountId::new(KeyPair::random().public_key().clone());
    test_client
        .submit::<InstructionBox>(
            MultisigRegister::with_account(multisig_seed_account_id, domain, spec.clone()).into(),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .wrap_err("register multisig account for cancel test")?;
    let multisig_account_id = canonical_multisig_account_id(&spec);
    let proposal_key: Name = "cancel_marker".parse().unwrap();
    let instructions = vec![
        SetKeyValue::account(
            multisig_account_id.clone(),
            proposal_key,
            Json::from("still-pending"),
        )
        .into(),
    ];
    let instructions_hash = HashOf::new(&instructions).to_string();
    let target_id = occurrence(&test_client, &multisig_account_id, proposal_nonce(1));
    test_client
        .submit::<InstructionBox>(
            MultisigPropose::new(
                multisig_account_id.clone(),
                proposal_nonce(1),
                instructions,
                None,
            )
            .into(),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .wrap_err("submit tarlookup multisig proposal")?;
    let selector = MultisigAccountSelectorDto {
        multisig_account_id: Some(multisig_account_id.clone()),
        multisig_account_alias: None,
    };
    let torii_base = network
        .peers()
        .first()
        .expect("network should expose at least one peer")
        .torii_url()
        .to_string();
    let propose_cancel = post_torii_app_json(
        &rt,
        &format!("{torii_base}/v1/multisig/cancel"),
        &MultisigCancelRequestDto {
            selector: selector.clone(),
            signer_account_id: BOB_ID.clone(),
            public_key_hex: None,
            signature_b64: None,
            creation_time_ms: None,
            fee_payment: FeePaymentIntent::authority(Vec::new(), None),
            proposal_nonce: proposal_nonce(2),
            target_proposal_id: target_id,
            target_instructions_hash: instructions_hash.parse()?,
        },
    )?;
    assert_eq!(
        propose_cancel
            .get("target_proposal_id")
            .and_then(JsonValue::as_str),
        Some(target_id.to_string().as_str())
    );
    let cancel_proposal_id = propose_cancel
        .get("cancel_proposal_id")
        .and_then(JsonValue::as_str)
        .expect("cancel proposal id should be returned")
        .to_owned();
    let target_instructions_hash = instructions_hash.parse().unwrap();
    let cancel_instructions = vec![
        MultisigCancel::new(
            multisig_account_id.clone(),
            target_id,
            target_instructions_hash,
        )
        .into(),
    ];
    let cancel_instructions_hash = HashOf::new(&cancel_instructions);
    let expected_cancel_proposal_id =
        occurrence(&test_client, &multisig_account_id, proposal_nonce(2));
    assert_eq!(
        cancel_proposal_id,
        expected_cancel_proposal_id.to_string(),
        "cancel route must bind the original cancellation nonce"
    );
    alt_client((BOB_ID.clone(), BOB_KEYPAIR.clone()), &test_client)
        .submit::<InstructionBox>(
            MultisigPropose::new(
                multisig_account_id.clone(),
                proposal_nonce(2),
                cancel_instructions,
                None,
            )
            .into(),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .wrap_err("submit cancel wrapper proposal for cancel route test")?;
    test_client
        .submit::<InstructionBox>(
            MultisigApprove::new(
                multisig_account_id.clone(),
                expected_cancel_proposal_id,
                cancel_instructions_hash,
            )
            .into(),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .wrap_err("submit cancel wrapper approval for cancel route test")?;
    let canceled = wait_for_multisig_proposal_status(
        &rt,
        &torii_base,
        &selector,
        &target_id.to_string(),
        "CANCELED",
    )
    .wrap_err("wait for canceled terminal state")?;
    assert_eq!(
        canceled.get("status").and_then(JsonValue::as_str),
        Some("CANCELED")
    );
    assert!(
        canceled
            .get("terminal_at_ms")
            .and_then(JsonValue::as_u64)
            .is_some(),
        "terminal proposal state should expose cancellation time"
    );
    let canceled_query = post_torii_app_json(
        &rt,
        &format!("{torii_base}/v1/multisig/proposals/query"),
        &MultisigProposalsQueryRequestDto {
            selector,
            status: vec!["CANCELED".to_owned()],
            cursor: None,
            limit: None,
        },
    )?;
    let proposals = canceled_query
        .get("proposals")
        .and_then(JsonValue::as_array)
        .expect("canceled proposals array");
    assert!(
        proposals.iter().any(|proposal| {
            proposal.get("proposal_id").and_then(JsonValue::as_str)
                == Some(target_id.to_string().as_str())
                && proposal.get("status").and_then(JsonValue::as_str) == Some("CANCELED")
        }),
        "canceled proposal should remain visible in terminal proposal queries"
    );
    Ok(())
}
#[test]
fn multisig_cli_list_all_resolves_hashed_role_suffixes() -> Result<()> {
    let context = stringify!(multisig_cli_list_all_resolves_hashed_role_suffixes);
    let cli_program =
        iroha_program().wrap_err("resolve `iroha` CLI before creating expiring proposals")?;
    let builder = NetworkBuilder::new().with_min_peers(4);
    let Some((network, _rt)) = start_network(builder, context) else {
        return Ok(());
    };
    let test_client = network.client();
    if !multisig_supported(&test_client) {
        eprintln!("skipping {context}: executor does not support multisig");
        return Ok(());
    }
    let domain: DomainId = DomainId::try_new("multisig-cli-hash-list", "universal").unwrap();
    register_runtime_domain_and_transfer_to_bob(&network, &test_client, &domain)
        .wrap_err("register multisig CLI test domain")?;
    let signatories = core::iter::repeat_with(|| gen_account_in(&domain))
        .take(8)
        .collect::<BTreeMap<AccountId, KeyPair>>();
    alt_client((BOB_ID.clone(), BOB_KEYPAIR.clone()), &test_client)
        .submit_all(
            signatories
                .keys()
                .cloned()
                .map(|account_id| Account::new(account_id.clone()))
                .map(Register::account),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .wrap_err("register multisig CLI signatories")?;
    let spec = MultisigSpec::new(
        signatories
            .keys()
            .cloned()
            .map(|account_id| (account_id, 1))
            .collect(),
        NonZeroU16::new(signatories.len().try_into().unwrap()).unwrap(),
        NonZeroU64::new(60_000).unwrap(),
    );
    let multisig_seed_account_id = AccountId::new(KeyPair::random().public_key().clone());
    alt_client((BOB_ID.clone(), BOB_KEYPAIR.clone()), &test_client)
        .submit::<InstructionBox>(
            MultisigRegister::with_account(multisig_seed_account_id, domain.clone(), spec.clone())
                .into(),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .wrap_err("register multisig account for CLI hash listing test")?;
    let multisig_account_id = canonical_multisig_account_id(&spec);
    let canonical_i105 = multisig_account_id
        .canonical_i105()
        .wrap_err("render multisig account as canonical I105")?;
    assert!(
        canonical_i105.len() > 128,
        "test precondition failed: multisig account should require a hashed role suffix"
    );
    let proposer = signatories
        .iter()
        .next()
        .map(|(account_id, key_pair)| (account_id.clone(), key_pair.clone()))
        .expect("signatory set must not be empty");
    let proposer_roles = test_client
        .client()
        .query(FindRolesByAccountId::new(proposer.0.clone()))
        .execute_all()
        .wrap_err("fetch proposer roles after multisig registration")?;
    assert!(
        proposer_roles
            .iter()
            .filter_map(multisig_role_suffix)
            .any(|suffix| {
                suffix != canonical_i105 && AccountId::parse_encoded(suffix).is_err()
            }),
        "proposer should receive a hashed MULTISIG_SIGNATORY role for the long multisig account"
    );
    let proposer_client = alt_client(proposer.clone(), &test_client);
    let mut expected_proposal_ids = Vec::new();
    for suffix in ["a", "b", "c"] {
        let marker: Name = format!("cli_pending_marker_{suffix}").parse().unwrap();
        let instructions = vec![
            SetKeyValue::account(
                multisig_account_id.clone(),
                marker,
                Json::new(format!("pending-{suffix}")),
            )
            .into(),
        ];
        let nonce = proposal_nonce(suffix.as_bytes()[0]);
        let proposal_id = occurrence(&test_client, &multisig_account_id, nonce).to_string();
        proposer_client
            .submit::<InstructionBox>(
                MultisigPropose::new(multisig_account_id.clone(), nonce, instructions, None).into(),
                FeePaymentIntent::authority(Vec::new(), None),
            )
            .wrap_err_with(|| format!("submit multisig proposal `{proposal_id}` for CLI test"))?;
        expected_proposal_ids.push(proposal_id);
    }
    let expected_proposals = wait_for_multisig_proposals(
        &proposer_client,
        &multisig_account_id,
        expected_proposal_ids.len(),
    )
    .wrap_err("wait for selector-explicit proposals before invoking CLI")?;
    let multisig_selector = multisig_account_id.to_string();
    let json_output = run_multisig_list_all_cli(
        &cli_program,
        &proposer_client,
        &proposer.1,
        &multisig_selector,
        &["--output-format", "json"],
    )?;
    assert!(
        json_output.status.success(),
        "CLI exited with status {} and stderr: {}",
        json_output.status,
        String::from_utf8_lossy(&json_output.stderr)
    );
    let payload: JsonValue = norito::json::from_slice(&json_output.stdout)
        .wrap_err("decode CLI multisig list JSON output")?;
    let proposals = payload
        .as_array()
        .expect("CLI multisig list should emit a JSON array");
    assert_eq!(
        proposals.len(),
        expected_proposals.len(),
        "CLI JSON output should mirror the selector-explicit proposal page set"
    );
    let expected_multisig_id = multisig_account_id.to_string();
    let proposal = proposals
        .iter()
        .find(|proposal| {
            proposal.get("proposal_id").and_then(JsonValue::as_str)
                == expected_proposal_ids
                    .first()
                    .map(std::string::String::as_str)
        })
        .unwrap_or_else(|| {
            panic!(
                "CLI should surface the pending proposal discovered via the hashed role suffix; expected proposal ids {expected_proposal_ids:?}, payload {payload:?}"
            );
        });
    let expected_entry = expected_proposals
        .iter()
        .find(|entry| {
            Some(entry.proposal_id.as_str()) == expected_proposal_ids.first().map(String::as_str)
        })
        .expect("expected proposal entry");
    assert!(
        proposals.iter().all(|entry| {
            entry.get("multisig_account_id").and_then(JsonValue::as_str)
                == Some(expected_multisig_id.as_str())
        }),
        "every CLI proposal entry should remain bound to the explicit multisig account id"
    );
    assert_eq!(
        proposal.get("status").and_then(JsonValue::as_str),
        Some(COLLECTING_SIGNATURES_STATUS)
    );
    assert_eq!(
        proposal.get("operation_type").and_then(JsonValue::as_str),
        Some(expected_entry.operation_type.as_str())
    );
    assert_eq!(
        proposal.get("proposal_id").and_then(JsonValue::as_str),
        Some(expected_entry.proposal_id.as_str())
    );
    let text_output = run_multisig_list_all_cli(
        &cli_program,
        &proposer_client,
        &proposer.1,
        &multisig_selector,
        &["--output-format", "text"],
    )?;
    assert!(
        text_output.status.success(),
        "text CLI exited with status {} and stderr: {}",
        text_output.status,
        String::from_utf8_lossy(&text_output.stderr)
    );
    let text = String::from_utf8(text_output.stdout).expect("text output should be UTF-8");
    let blocks = text.trim().split("\n\n").collect::<Vec<_>>();
    assert_eq!(
        blocks.len(),
        expected_proposals.len(),
        "text output should contain one block per proposal entry"
    );
    let first_text_entry = &expected_proposals[0];
    assert!(blocks[0].contains(&format!("multisig_account_id: {}", multisig_account_id)));
    assert!(blocks[0].contains(&format!("proposal_id: {}", first_text_entry.proposal_id)));
    assert!(blocks[0].contains("status: COLLECTING_SIGNATURES"));
    assert!(blocks[0].contains(&format!(
        "operation_type: {}",
        first_text_entry.operation_type
    )));
    assert!(blocks[0].contains(&format!(
        "proposed_at_ms: {}",
        first_text_entry.proposal.proposed_at_ms
    )));
    let paged_output = run_multisig_list_all_cli(
        &cli_program,
        &proposer_client,
        &proposer.1,
        &multisig_selector,
        &[
            "--output-format",
            "json",
            "--fetch-size",
            "1",
            "--offset",
            "1",
            "--limit",
            "2",
        ],
    )?;
    assert!(
        paged_output.status.success(),
        "paged CLI exited with status {} and stderr: {}",
        paged_output.status,
        String::from_utf8_lossy(&paged_output.stderr)
    );
    let paged_payload: JsonValue = norito::json::from_slice(&paged_output.stdout)
        .wrap_err("decode paged CLI multisig list JSON output")?;
    let paged_items = paged_payload
        .as_array()
        .expect("paged CLI multisig list should emit a JSON array");
    let paged_ids = paged_items
        .iter()
        .map(|entry| {
            entry
                .get("proposal_id")
                .and_then(JsonValue::as_str)
                .expect("proposal_id")
                .to_owned()
        })
        .collect::<Vec<_>>();
    let expected_paged_ids = expected_proposals
        .iter()
        .skip(1)
        .take(2)
        .map(|entry| entry.proposal_id.clone())
        .collect::<Vec<_>>();
    assert_eq!(paged_ids, expected_paged_ids);
    Ok(())
}
#[test]
fn multisig_register_materializes_missing_signatory_account() -> Result<()> {
    let context = stringify!(multisig_register_materializes_missing_signatory_account);
    let builder = NetworkBuilder::new();
    let Some((network, _rt)) = start_network(builder, context) else {
        return Ok(());
    };
    let test_client = network.client();
    if !multisig_supported(&test_client) {
        eprintln!("skipping {context}: executor does not support multisig register");
        return Ok(());
    }
    let domain: DomainId = DomainId::try_new("multisig-register-materialize", "universal").unwrap();
    register_runtime_domain_and_transfer_to_bob(&network, &test_client, &domain)?;
    let existing_signer = gen_account_in(&domain);
    alt_client((BOB_ID.clone(), BOB_KEYPAIR.clone()), &test_client).submit(
        Register::account(Account::new(existing_signer.0.clone())),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    let missing_signer = gen_account_in(&domain);
    let spec = MultisigSpec::new(
        BTreeMap::from([
            (existing_signer.0.clone(), 1),
            (missing_signer.0.clone(), 1),
        ]),
        NonZeroU16::new(2).unwrap(),
        NonZeroU64::MAX,
    );
    let seed_account = AccountId::new(KeyPair::random().public_key().clone());
    alt_client((BOB_ID.clone(), BOB_KEYPAIR.clone()), &test_client).submit::<InstructionBox>(
        MultisigRegister::with_account(seed_account, domain.clone(), spec).into(),
        FeePaymentIntent::authority(Vec::new(), None),
    )?;
    let created_via_key: Name = "iroha:created_via".parse().unwrap();
    let created = wait_for_account_visibility(
        &test_client,
        &missing_signer.0,
        "multisig register materialization",
    )?;
    assert_eq!(
        created.metadata().get(&created_via_key),
        Some(&Json::new("multisig")),
        "materialized signatory should be marked as multisig-created"
    );
    Ok(())
}
#[test]
fn multisig_materialized_signatory_can_propose_and_approve() -> Result<()> {
    let context = stringify!(multisig_materialized_signatory_can_propose_and_approve);
    let builder = NetworkBuilder::new().with_min_peers(4);
    let Some((network, _rt)) = start_network(builder, context) else {
        return Ok(());
    };
    let test_client = network.client();
    if !multisig_supported(&test_client) {
        eprintln!("skipping {context}: executor does not support multisig register");
        return Ok(());
    }
    let domain: DomainId = DomainId::try_new("multisig-materialized-author", "universal").unwrap();
    register_runtime_domain_and_transfer_to_bob(&network, &test_client, &domain)?;
    let existing_signer = gen_account_in(&domain);
    alt_client((BOB_ID.clone(), BOB_KEYPAIR.clone()), &test_client).submit(
        Register::account(Account::new(existing_signer.0.clone())),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    let missing_signer = gen_account_in(&domain);
    assert!(
        find_account(&test_client, &missing_signer.0)?.is_none(),
        "precondition: missing signatory must not exist before multisig registration"
    );
    let spec = MultisigSpec::new(
        BTreeMap::from([
            (existing_signer.0.clone(), 1),
            (missing_signer.0.clone(), 1),
        ]),
        NonZeroU16::new(2).unwrap(),
        NonZeroU64::MAX,
    );
    let seed_account = AccountId::new(KeyPair::random().public_key().clone());
    alt_client((BOB_ID.clone(), BOB_KEYPAIR.clone()), &test_client)
        .submit::<InstructionBox>(
            MultisigRegister::with_account(seed_account, domain.clone(), spec.clone()).into(),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .wrap_err("register multisig account with one missing signatory")?;
    let created_via_key: Name = "iroha:created_via".parse().unwrap();
    let materialized = wait_for_account_visibility(
        &test_client,
        &missing_signer.0,
        "materialized signatory authoring",
    )?;
    assert_eq!(
        materialized.metadata().get(&created_via_key),
        Some(&Json::new("multisig")),
        "materialized signatory should be marked as multisig-created"
    );
    assert!(
        materialized.controller().single_signatory().is_some(),
        "materialized signatory must remain a single-key authority"
    );
    let multisig_account_id = canonical_multisig_account_id(&spec);
    let marker: Name = "materialized_author_marker".parse().unwrap();
    let marker_value = Json::new("materialized-approved");
    let instructions = vec![
        SetKeyValue::account(
            multisig_account_id.clone(),
            marker.clone(),
            marker_value.clone(),
        )
        .into(),
    ];
    let instructions_hash = HashOf::new(&instructions);
    let nonce = proposal_nonce(1);
    let proposal_id = occurrence(&test_client, &multisig_account_id, nonce);
    let proposer_client = alt_client(missing_signer.clone(), &test_client);
    let propose = MultisigPropose::new(
        multisig_account_id.clone(),
        nonce,
        instructions.clone(),
        None,
    );
    let proposal_tx = {
        let account = proposer_client.account_client();
        account
            .prepare_transaction(iroha::client::AccountTransactionDraft::new(
                core::iter::once::<InstructionBox>(propose.into()),
                FeePaymentIntent::authority(Vec::new(), None),
                Metadata::default(),
            ))
            .and_then(|payload| account.sign_transaction(payload))
    }
    .expect("build integration-test transaction");
    assert_eq!(
        proposal_tx.authority().subject_id(),
        missing_signer.0.subject_id(),
        "proposal transaction authority subject must match materialized proposer"
    );
    assert!(
        proposal_tx
            .authority()
            .controller()
            .single_signatory()
            .is_some(),
        "proposal transaction authority must stay single-key: {}",
        proposal_tx.authority()
    );
    proposer_client
        .submit_transaction_and_wait(&proposal_tx)
        .wrap_err("materialized signatory should submit multisig proposal")?;
    assert!(
        find_account(&test_client, &multisig_account_id)?
            .and_then(|account| account.metadata().get(&marker).cloned())
            .is_none(),
        "proposal alone must not execute before quorum approval"
    );
    let approver_client = alt_client(existing_signer.clone(), &test_client);
    let approve: InstructionBox =
        MultisigApprove::new(multisig_account_id.clone(), proposal_id, instructions_hash).into();
    let approve_tx = {
        let account = approver_client.account_client();
        account
            .prepare_transaction(iroha::client::AccountTransactionDraft::new(
                core::iter::once::<InstructionBox>(approve),
                FeePaymentIntent::authority(Vec::new(), None),
                Metadata::default(),
            ))
            .and_then(|payload| account.sign_transaction(payload))
    }
    .expect("build integration-test transaction");
    assert_eq!(
        approve_tx.authority().subject_id(),
        existing_signer.0.subject_id(),
        "approval transaction authority subject must match existing approver"
    );
    assert!(
        approve_tx
            .authority()
            .controller()
            .single_signatory()
            .is_some(),
        "approval transaction authority must stay single-key: {}",
        approve_tx.authority()
    );
    approver_client
        .submit_transaction_and_wait(&approve_tx)
        .wrap_err("existing signatory should approve materialized proposal")?;
    let executed = wait_for_account_metadata_value(
        &test_client,
        &multisig_account_id,
        &marker,
        "materialized signatory multisig execution",
    )?;
    assert_eq!(
        executed, marker_value,
        "multisig quorum should execute the proposed metadata write"
    );
    Ok(())
}
#[test]
fn multisig_register_by_non_signatory_materializes_missing_signatory_account() -> Result<()> {
    let context =
        stringify!(multisig_register_by_non_signatory_materializes_missing_signatory_account);
    let builder = NetworkBuilder::new();
    let Some((network, _rt)) = start_network(builder, context) else {
        return Ok(());
    };
    let test_client = network.client();
    if !multisig_supported(&test_client) {
        eprintln!("skipping {context}: executor does not support multisig register");
        return Ok(());
    }
    let domain: DomainId =
        DomainId::try_new("multisig-register-rejected-materialize", "universal").unwrap();
    register_runtime_domain_and_transfer_to_bob(&network, &test_client, &domain)?;
    let existing_signer = gen_account_in(&domain);
    let non_signatory = gen_account_in(&domain);
    let register_accounts: [InstructionBox; 2] = [
        Register::account(Account::new(existing_signer.0.clone())).into(),
        Register::account(Account::new(non_signatory.0.clone())).into(),
    ];
    alt_client((BOB_ID.clone(), BOB_KEYPAIR.clone()), &test_client).submit_all(
        register_accounts,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    let missing_signer = gen_account_in(&domain);
    let spec = MultisigSpec::new(
        BTreeMap::from([
            (existing_signer.0.clone(), 1),
            (missing_signer.0.clone(), 1),
        ]),
        NonZeroU16::new(2).unwrap(),
        NonZeroU64::MAX,
    );
    let seed_account = AccountId::new(KeyPair::random().public_key().clone());
    let register = MultisigRegister::with_account(seed_account, domain.clone(), spec);
    alt_client(non_signatory, &test_client)
        .submit::<InstructionBox>(
            register.into(),
            iroha::data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .expect("non-signatory should register multisig without a separate grant");
    let created_via_key: Name = "iroha:created_via".parse().unwrap();
    let created = wait_for_account_visibility(
        &test_client,
        &missing_signer.0,
        "non-signatory multisig register materialization",
    )?;
    assert_eq!(
        created.metadata().get(&created_via_key),
        Some(&Json::new("multisig")),
        "materialized signatory should be marked as multisig-created"
    );
    Ok(())
}
#[test]
fn multisig_register_materializes_missing_signatory_account_after_executor_upgrade() -> Result<()> {
    let context =
        stringify!(multisig_register_materializes_missing_signatory_account_after_executor_upgrade);
    let builder = NetworkBuilder::new().with_ivm_fuel(IvmFuelConfig::Auto);
    let Some((network, _rt)) = start_network(builder, context) else {
        return Ok(());
    };
    let test_client = network.client();
    if !multisig_supported(&test_client) {
        eprintln!("skipping {context}: executor does not support multisig register");
        return Ok(());
    }
    let domain: DomainId =
        DomainId::try_new("multisig-register-materialize-upgraded", "universal").unwrap();
    register_runtime_domain_and_transfer_to_bob(&network, &test_client, &domain)?;
    // This regression targets multisig account materialization after the executor
    // upgrade. Keep the domain bootstrap on the pre-upgrade executor so the test
    // stays scoped to the multisig path rather than unrelated domain admission.
    upgrade_executor(&test_client)?;
    let existing_signer = gen_account_in(&domain);
    alt_client((BOB_ID.clone(), BOB_KEYPAIR.clone()), &test_client).submit(
        Register::account(Account::new(existing_signer.0.clone())),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    let missing_signer = gen_account_in(&domain);
    let spec = MultisigSpec::new(
        BTreeMap::from([
            (existing_signer.0.clone(), 1),
            (missing_signer.0.clone(), 1),
        ]),
        NonZeroU16::new(2).unwrap(),
        NonZeroU64::MAX,
    );
    let seed_account = AccountId::new(KeyPair::random().public_key().clone());
    alt_client((BOB_ID.clone(), BOB_KEYPAIR.clone()), &test_client).submit::<InstructionBox>(
        MultisigRegister::with_account(seed_account, domain.clone(), spec).into(),
        FeePaymentIntent::authority(Vec::new(), None),
    )?;
    let created_via_key: Name = "iroha:created_via".parse().unwrap();
    let created = wait_for_account_visibility(
        &test_client,
        &missing_signer.0,
        "post-upgrade multisig register materialization",
    )?;
    assert_eq!(
        created.metadata().get(&created_via_key),
        Some(&Json::new("multisig")),
        "materialized signatory should be marked as multisig-created"
    );
    Ok(())
}
#[test]
fn multisig_register_by_non_signatory_materializes_missing_signatory_account_after_executor_upgrade()
-> Result<()> {
    let context = stringify!(
        multisig_register_by_non_signatory_materializes_missing_signatory_account_after_executor_upgrade
    );
    let builder = NetworkBuilder::new().with_ivm_fuel(IvmFuelConfig::Auto);
    let Some((network, _rt)) = start_network(builder, context) else {
        return Ok(());
    };
    let test_client = network.client();
    if !multisig_supported(&test_client) {
        eprintln!("skipping {context}: executor does not support multisig register");
        return Ok(());
    }
    let domain: DomainId =
        DomainId::try_new("multisig-register-rejected-upgraded", "universal").unwrap();
    register_runtime_domain_and_transfer_to_bob(&network, &test_client, &domain)?;
    // Keep domain bootstrap outside the upgraded executor so this test continues
    // to isolate the post-upgrade multisig register behavior it actually covers.
    upgrade_executor(&test_client)?;
    let existing_signer = gen_account_in(&domain);
    let non_signatory = gen_account_in(&domain);
    let register_accounts: [InstructionBox; 2] = [
        Register::account(Account::new(existing_signer.0.clone())).into(),
        Register::account(Account::new(non_signatory.0.clone())).into(),
    ];
    alt_client((BOB_ID.clone(), BOB_KEYPAIR.clone()), &test_client).submit_all(
        register_accounts,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    let missing_signer = gen_account_in(&domain);
    let spec = MultisigSpec::new(
        BTreeMap::from([
            (existing_signer.0.clone(), 1),
            (missing_signer.0.clone(), 1),
        ]),
        NonZeroU16::new(2).unwrap(),
        NonZeroU64::MAX,
    );
    let seed_account = AccountId::new(KeyPair::random().public_key().clone());
    let register = MultisigRegister::with_account(seed_account, domain.clone(), spec);
    alt_client(non_signatory, &test_client)
        .submit::<InstructionBox>(
            register.into(),
            iroha::data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .expect("non-signatory should register multisig without a separate grant");
    let created_via_key: Name = "iroha:created_via".parse().unwrap();
    let created = wait_for_account_visibility(
        &test_client,
        &missing_signer.0,
        "non-signatory post-upgrade multisig register materialization",
    )?;
    assert_eq!(
        created.metadata().get(&created_via_key),
        Some(&Json::new("multisig")),
        "materialized signatory should be marked as multisig-created"
    );
    Ok(())
}
#[test]
fn multisig_add_signatory_materializes_missing_account() -> Result<()> {
    let context = stringify!(multisig_add_signatory_materializes_missing_account);
    let builder = NetworkBuilder::new();
    let Some((network, _rt)) = start_network(builder, context) else {
        return Ok(());
    };
    let test_client = network.client();
    if !multisig_supported(&test_client) {
        eprintln!("skipping {context}: executor does not advertise multisig instructions");
        return Ok(());
    }
    let domain: DomainId = DomainId::try_new("multisig-auto-materialize", "universal").unwrap();
    register_runtime_domain_and_transfer_to_bob(&network, &test_client, &domain)?;
    let existing_signer = gen_account_in(&domain);
    alt_client((BOB_ID.clone(), BOB_KEYPAIR.clone()), &test_client).submit(
        Register::account(Account::new(existing_signer.0.clone())),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    let spec = MultisigSpec::new(
        BTreeMap::from([(existing_signer.0.clone(), 1)]),
        NonZeroU16::new(1).unwrap(),
        NonZeroU64::MAX,
    );
    let seed_account = AccountId::new(KeyPair::random().public_key().clone());
    alt_client((BOB_ID.clone(), BOB_KEYPAIR.clone()), &test_client).submit::<InstructionBox>(
        MultisigRegister::with_account(seed_account.clone(), domain.clone(), spec.clone()).into(),
        FeePaymentIntent::authority(Vec::new(), None),
    )?;
    let multisig_account_id = canonical_multisig_account_id(&spec);
    let missing_signer = gen_account_in(&domain);
    assert!(
        find_account(&test_client, &missing_signer.0)?.is_none(),
        "precondition: missing signatory must not exist"
    );
    alt_client((BOB_ID.clone(), BOB_KEYPAIR.clone()), &test_client).submit::<InstructionBox>(
        AddSignatory::new(multisig_account_id, missing_signer.1.public_key().clone()).into(),
        FeePaymentIntent::authority(Vec::new(), None),
    )?;
    let created_via_key: Name = "iroha:created_via".parse().unwrap();
    let created = wait_for_account_visibility(
        &test_client,
        &missing_signer.0,
        "multisig add-signatory materialization",
    )?;
    assert_eq!(
        created.metadata().get(&created_via_key),
        Some(&Json::new("multisig")),
        "materialized account should be marked as multisig-created"
    );
    Ok(())
}
#[test]
fn multisig_add_signatory_rejected_does_not_materialize_missing_account() -> Result<()> {
    let context = stringify!(multisig_add_signatory_rejected_does_not_materialize_missing_account);
    let builder = NetworkBuilder::new();
    let Some((network, _rt)) = start_network(builder, context) else {
        return Ok(());
    };
    let test_client = network.client();
    if !multisig_supported(&test_client) {
        eprintln!("skipping {context}: executor does not support multisig register");
        return Ok(());
    }
    let domain: DomainId =
        DomainId::try_new("multisig-add-rejected-materialize", "universal").unwrap();
    register_runtime_domain_and_transfer_to_bob(&network, &test_client, &domain)?;
    let existing_signer = gen_account_in(&domain);
    alt_client((BOB_ID.clone(), BOB_KEYPAIR.clone()), &test_client).submit(
        Register::account(Account::new(existing_signer.0.clone())),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )?;
    let seed_account = AccountId::new(KeyPair::random().public_key().clone());
    let spec = MultisigSpec::new(
        BTreeMap::from([(existing_signer.0.clone(), 1)]),
        NonZeroU16::new(1).unwrap(),
        NonZeroU64::MAX,
    );
    alt_client((BOB_ID.clone(), BOB_KEYPAIR.clone()), &test_client).submit::<InstructionBox>(
        MultisigRegister::with_account(seed_account.clone(), domain.clone(), spec.clone()).into(),
        FeePaymentIntent::authority(Vec::new(), None),
    )?;
    let multisig_account_id = canonical_multisig_account_id(&spec);
    let missing_signer = gen_account_in(&domain);
    let ghost_authority = gen_account_in(&domain);
    assert!(
        find_account(&test_client, &ghost_authority.0)?.is_none(),
        "precondition: authority account must not exist on ledger"
    );
    let _err = alt_client(ghost_authority, &test_client)
        .submit::<InstructionBox>(
            AddSignatory::new(multisig_account_id, missing_signer.1.public_key().clone()).into(),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .expect_err("missing authority must not add signatory");
    let missing_found = find_account(&test_client, &missing_signer.0)?.is_some();
    assert!(
        !missing_found,
        "rejected add-signatory must not materialize missing accounts"
    );
    Ok(())
}
struct TestSuite {
    domain: DomainId,
    unauthorized_target_opt: Option<AccountId>,
    transaction_ttl_ms_opt: Option<u64>,
}
impl TestSuite {
    fn new(
        domain: DomainId,
        unauthorized_target_opt: Option<AccountId>,
        transaction_ttl_ms_opt: Option<u64>,
    ) -> Self {
        Self {
            domain,
            unauthorized_target_opt,
            transaction_ttl_ms_opt,
        }
    }
    fn normal() -> Self {
        // New domain for this test
        let domain = DomainId::try_new("kingdom", "universal").unwrap();
        // Make some changes to the multisig account itself
        let unauthorized_target_opt = None;
        // Semi-permanently valid
        let transaction_ttl_ms_opt = None;
        Self::new(domain, unauthorized_target_opt, transaction_ttl_ms_opt)
    }
    fn unauthorized() -> Self {
        let domain = DomainId::try_new("kingdom", "universal").unwrap();
        // A target account that is not present on-ledger, ensuring the proposal execution fails
        // on final validation instead of mutating unrelated account metadata.
        let unauthorized_target_opt = Some(AccountId::new(KeyPair::random().public_key().clone()));
        Self::new(domain, unauthorized_target_opt, None)
    }
    fn expires() -> Self {
        let domain = DomainId::try_new("kingdom", "universal").unwrap();
        // Expires after 1 sec
        let transaction_ttl_ms_opt = Some(1_000);
        Self::new(domain, None, transaction_ttl_ms_opt)
    }
}
/// # Scenario
///
/// 1. Signatories are populated and ready to join a multisig account
/// 2. An arbitrary account registers a multisig account for the domain
/// 3. One of the signatories of the multisig account proposes a multisig transaction
/// 4. Other signatories approve the multisig transaction
/// 5. The multisig transaction executes when all of the following are met:
///     - Quorum reached: authenticated
///     - Transaction has not expired
///     - Every instruction validated against the multisig account: authorized
/// 6. Either execution or expiration on approval deletes the transaction entry
#[expect(clippy::cast_possible_truncation)]
fn multisig_base(suite: TestSuite, context: &'static str) -> Result<()> {
    const N_SIGNATORIES: usize = 5;
    let TestSuite {
        domain,
        unauthorized_target_opt,
        transaction_ttl_ms_opt,
    } = suite;
    let builder = NetworkBuilder::new();
    let Some((network, _rt)) = start_network(builder, context) else {
        return Ok(());
    };
    let test_client = network.client();
    if !multisig_supported(&test_client) {
        eprintln!("skipping {context}: executor does not advertise multisig instructions");
        return Ok(());
    }
    // Assume some domain registered after genesis
    register_runtime_domain(&network, &test_client, &domain)
        .wrap_err("register multisig test domain")?;
    // Populate residents in the domain
    let mut residents = core::iter::repeat_with(|| gen_account_in(&domain))
        .take(1 + N_SIGNATORIES)
        .collect::<BTreeMap<AccountId, KeyPair>>();
    test_client
        .submit_all(
            residents
                .keys()
                .cloned()
                .map(|id| Account::new(id.clone()))
                .map(Register::account),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .wrap_err("register multisig test residents")?;
    let non_signatory = residents.pop_first().unwrap();
    let mut signatories = residents;
    let spec = MultisigSpec::new(
        signatories
            .keys()
            .enumerate()
            .map(|(weight, id)| (id.clone(), 1 + weight as u8))
            .collect(),
        // Quorum can be reached without the first signatory
        (1..=N_SIGNATORIES)
            .skip(1)
            .sum::<usize>()
            .try_into()
            .ok()
            .and_then(NonZeroU16::new)
            .unwrap(),
        transaction_ttl_ms_opt
            .and_then(NonZeroU64::new)
            .unwrap_or(NonZeroU64::MAX),
    );
    let multisig_account_key = KeyPair::random();
    let multisig_seed_account_id = AccountId::new(multisig_account_key.public_key().clone());
    let register_multisig_account = MultisigRegister::with_account(
        multisig_seed_account_id.clone(),
        domain.clone(),
        spec.clone(),
    );
    alt_client(
        (CARPENTER_ID.clone(), CARPENTER_KEYPAIR.clone()),
        &test_client,
    )
    .submit::<InstructionBox>(
        register_multisig_account.into(),
        iroha::data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .expect("multisig account should be registered by an arbitrary account");
    let resident_ids: Vec<AccountId> = core::iter::once(non_signatory.0.clone())
        .chain(signatories.keys().cloned())
        .collect();
    let accounts_after_register = test_client
        .client()
        .query(FindAccounts::new())
        .execute_all()
        .wrap_err("fetch accounts after multisig registration")?;
    for resident_id in resident_ids {
        let account = accounts_after_register
            .iter()
            .find(|account| account.id() == &resident_id)
            .expect("resident account should remain materialized after multisig registration");
        assert!(
            account.controller().single_signatory().is_some(),
            "resident account unexpectedly became multisig: {}",
            account.id()
        );
    }
    // All but the first signatory approve the proposal.
    let _non_approving_signatory = signatories.pop_first().unwrap();
    let multisig_account_id = canonical_multisig_account_id(&spec);
    let key: Name = "success_marker".parse().unwrap();
    let transaction_target = unauthorized_target_opt
        .as_ref()
        .unwrap_or(&multisig_account_id)
        .clone();
    let instructions = vec![
        SetKeyValue::account(
            transaction_target.clone(),
            key.clone(),
            Json::from("congratulations"),
        )
        .into(),
    ];
    let instructions_hash = HashOf::new(&instructions);
    let nonce = proposal_nonce(1);
    let proposal_id = occurrence(&test_client, &multisig_account_id, nonce);
    let proposer = signatories.pop_last().unwrap();
    let mut approvers = signatories.into_iter();
    let propose = MultisigPropose::new(multisig_account_id.clone(), nonce, instructions, None);
    let proposer_client = alt_client(proposer.clone(), &test_client);
    let proposer_account = test_client
        .client()
        .query(FindAccounts::new())
        .execute_all()?
        .into_iter()
        .find(|account| account.id() == &proposer.0)
        .expect("proposer account must exist before multisig proposal");
    assert!(
        proposer_account.controller().single_signatory().is_some(),
        "proposer account unexpectedly became multisig before proposal: {}",
        proposer_account.id()
    );
    let proposal_tx = {
        let account = proposer_client.account_client();
        account
            .prepare_transaction(iroha::client::AccountTransactionDraft::new(
                core::iter::once::<InstructionBox>(propose.into()),
                FeePaymentIntent::authority(Vec::new(), None),
                Metadata::default(),
            ))
            .and_then(|payload| account.sign_transaction(payload))
    }
    .expect("build integration-test transaction");
    assert_eq!(
        proposal_tx.authority().subject_id(),
        proposer.0.subject_id(),
        "proposal transaction authority subject must match proposer"
    );
    assert!(
        proposal_tx
            .authority()
            .controller()
            .single_signatory()
            .is_some(),
        "proposal transaction authority unexpectedly became multisig: {}",
        proposal_tx.authority()
    );
    proposer_client
        .submit_transaction_and_wait(&proposal_tx)
        .wrap_err("submit multisig proposal")?;
    // Allow time to elapse to test the expiration
    if let Some(ms) = transaction_ttl_ms_opt {
        std::thread::sleep(Duration::from_millis(ms))
    }
    test_client
        .submit(
            Log::new(Level::DEBUG, "Just ticking time".to_string()),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .wrap_err("tick time after multisig proposal")?;
    let approve: InstructionBox =
        MultisigApprove::new(multisig_account_id.clone(), proposal_id, instructions_hash).into();
    // Approve once to see if the proposal expires
    let approver = approvers.next().unwrap();
    alt_client(approver, &test_client)
        .submit::<InstructionBox>(
            approve.clone(),
            iroha::data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .wrap_err("submit first multisig approval")?;
    // Subsequent approvals should succeed unless the proposal is expired
    for _ in 0..(N_SIGNATORIES - 4) {
        let approver = approvers.next().unwrap();
        let res = alt_client(approver, &test_client).submit::<InstructionBox>(
            approve.clone(),
            iroha::data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        );
        match &transaction_ttl_ms_opt {
            None => {
                res.unwrap();
            }
            _ => {
                let _err = res.unwrap_err();
            }
        }
    }
    let fetch_account = |id: &AccountId| {
        test_client
            .client()
            .query(FindAccounts::new())
            .execute_all()
            .ok()
            .and_then(|accounts| accounts.into_iter().find(|account| account.id() == id))
    };
    // Check that the multisig transaction has not yet executed
    assert!(
        fetch_account(&transaction_target)
            .and_then(|account| account.metadata().get(&key).cloned())
            .is_none(),
        "instructions shouldn't execute without enough approvals"
    );
    // The last approve to proceed to validate and execute the instructions
    let approver = approvers.next().unwrap();
    let res = alt_client(approver, &test_client).submit::<InstructionBox>(
        approve.clone(),
        iroha::data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    );
    match (&transaction_ttl_ms_opt, &unauthorized_target_opt) {
        (None, None) => {
            res.unwrap();
        }
        _ => {
            let _err = res.unwrap_err();
        }
    }
    // Check if the multisig transaction has executed
    let res = fetch_account(&transaction_target)
        .and_then(|account| account.metadata().get(&key).cloned());
    match (&transaction_ttl_ms_opt, &unauthorized_target_opt) {
        (None, None) => {
            if res.is_none() {
                wait_for_account_metadata_value(
                    &test_client,
                    &transaction_target,
                    &key,
                    "multisig quorum execution",
                )?;
            }
        }
        _ => {
            assert!(res.is_none());
        }
    }
    // Check if the transaction entry is deleted
    let res = fetch_account(&multisig_account_id).and_then(|account| {
        account
            .metadata()
            .get(format!("multisig/proposals/{proposal_id}").as_str())
            .cloned()
    });
    // Proposals are removed once quorum processing runs, including unauthorized execution failures.
    assert!(res.is_none());
    Ok(())
}
/// # Scenario
///
/// ```
///         012345 <--- root multisig account
///        /      \
///       /        12345
///      /        /     \
///     /       12       345
///    /       /  \     / | \
///   0       1    2   3  4  5 <--- personal signatories
/// ```
fn multisig_recursion_base(context: &'static str) -> Result<()> {
    let builder = NetworkBuilder::new();
    let Some((network, _rt)) = start_network(builder, context) else {
        return Ok(());
    };
    let test_client = network.client();
    if !multisig_supported(&test_client) {
        eprintln!("skipping {context}: executor does not advertise multisig instructions");
        return Ok(());
    }
    let wonderland = "wonderland";
    let signatories = core::iter::repeat_with(|| gen_account_in(wonderland))
        .take(6)
        .collect::<BTreeMap<AccountId, KeyPair>>();
    let wonderland_domain = DomainId::try_new(wonderland, "universal").unwrap();
    test_client.submit_all(
        signatories
            .keys()
            .cloned()
            .map(|id| Account::new(id.clone()))
            .map(Register::account),
        FeePaymentIntent::authority(Vec::new(), None),
    )?;
    let mut sigs = signatories.clone();
    let sigs_345 = sigs.split_off(signatories.keys().nth(3).unwrap());
    let sigs_12 = sigs.split_off(signatories.keys().nth(1).unwrap());
    let register_ms_account = |sigs: Vec<&AccountId>| -> Result<AccountId> {
        let spec = MultisigSpec::new(
            sigs.iter().copied().map(|id| (id.clone(), 1)).collect(),
            sigs.len()
                .try_into()
                .ok()
                .and_then(NonZeroU16::new)
                .unwrap(),
            NonZeroU64::MAX,
        );
        let multisig_account_key = KeyPair::random();
        let seed_account_id = AccountId::new(multisig_account_key.public_key().clone());
        let register = MultisigRegister::with_account(
            seed_account_id.clone(),
            wonderland_domain.clone(),
            spec.clone(),
        );
        test_client
            .submit::<InstructionBox>(
                register.into(),
                iroha::data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
            .wrap_err("register multisig account in recursion setup")?;
        Ok(canonical_multisig_account_id(&spec))
    };
    let msa_12 = register_ms_account(sigs_12.keys().collect())?;
    let msa_345 = register_ms_account(sigs_345.keys().collect())?;
    let spec_with_nested_signatory = MultisigSpec::new(
        BTreeMap::from([(msa_12, 1), (msa_345, 1)]),
        NonZeroU16::new(2).unwrap(),
        NonZeroU64::MAX,
    );
    let seed_account_id = AccountId::new(KeyPair::random().public_key().clone());
    let register_nested = MultisigRegister::with_account(
        seed_account_id,
        wonderland_domain,
        spec_with_nested_signatory,
    );
    let err = test_client
        .submit::<InstructionBox>(
            register_nested.into(),
            iroha::data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .expect_err("nested multisig signatories must be rejected");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("single-key account"),
        "expected nested-signatory rejection to mention single-key requirement, got: {msg}"
    );
    Ok(())
}
#[test]
fn reserved_roles() {
    let builder = NetworkBuilder::new();
    let Some((network, _rt)) = start_network(builder, stringify!(reserved_roles)) else {
        return;
    };
    let test_client = network.client();
    let account_in_another_domain = gen_account_in("garden_of_live_flowers").0;
    let register = {
        let other_domain = "garden_of_live_flowers";
        let role = format!(
            "MULTISIG_SIGNATORY/{}/{}",
            other_domain,
            account_in_another_domain.expect_single_signatory()
        )
        .parse()
        .unwrap();
        Register::role(Role::new(role, ALICE_ID.clone()))
    };
    let _err = test_client
        .submit(
            register,
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .expect_err(
            "role with this name shouldn't be registered by anyone other than the domain owner",
        );
}
fn alt_client(signatory: (AccountId, KeyPair), base_client: &Client) -> Client {
    integration_tests::sync::rebind_blocking_client(base_client, |client| {
        client.account = signatory.0;
        client.key_pair = signatory.1;
    })
}
#[test]
fn inconclusive_domain_registration_error_matches_queue_timeout() {
    let err = eyre!("transaction queued for too long");
    assert!(is_inconclusive_domain_registration_error(&err));
}
#[test]
fn inconclusive_domain_registration_error_ignores_rejections() {
    let err = eyre!("domain registration rejected");
    assert!(!is_inconclusive_domain_registration_error(&err));
}
