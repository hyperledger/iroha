use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
    u64,
};

use eyre::Result;
use iroha::{
    client,
    crypto::KeyPair,
    data_model::{prelude::*, query::trigger::FindTriggers, Level},
};
use iroha_data_model::events::execute_trigger::ExecuteTriggerEventFilter;
use iroha_multisig_data_model::{MultisigAccountArgs, MultisigTransactionArgs};
use iroha_test_network::*;
use iroha_test_samples::{
    gen_account_in, ALICE_ID, BOB_ID, BOB_KEYPAIR, CARPENTER_ID, CARPENTER_KEYPAIR,
};

#[test]
fn multisig() -> Result<()> {
    multisig_base(None)
}

#[test]
fn multisig_expires() -> Result<()> {
    multisig_base(Some(2))
}

/// # Scenario
///
/// Proceeds from top left to bottom right. Starred operations are the responsibility of the user
///
/// ```
/// | world level               | domain level                | account level                   | transaction level    |
/// |---------------------------|-----------------------------|---------------------------------|----------------------|
/// | given domains initializer |                             |                                 |                      |
/// |                           | * creates domain            |                                 |                      |
/// |       domains initializer | generates accounts registry |                                 |                      |
/// |                           |                             | * creates signatories           |                      |
/// |                           |   * calls accounts registry | generates multisig account      |                      |
/// |                           |           accounts registry | generates transactions registry |                      |
/// |                           |                             |   * calls transactions registry | proposes transaction |
/// |                           |                             |   * calls transactions registry | approves transaction |
/// |                           |                             |           transactions registry | executes transaction |
/// ```
#[allow(clippy::cast_possible_truncation)]
fn multisig_base(transaction_ttl_ms: Option<u64>) -> Result<()> {
    const N_SIGNATORIES: usize = 5;

    let (network, _rt) = NetworkBuilder::new().start_blocking()?;
    let test_client = network.client();

    let kingdom: DomainId = "kingdom".parse().unwrap();

    // Assume some domain registered after genesis
    let register_and_transfer_kingdom: [InstructionBox; 2] = [
        Register::domain(Domain::new(kingdom.clone())).into(),
        Transfer::domain(ALICE_ID.clone(), kingdom.clone(), BOB_ID.clone()).into(),
    ];
    test_client.submit_all_blocking(register_and_transfer_kingdom)?;

    // One more block to generate a multisig accounts registry for the domain
    test_client.submit_blocking(Log::new(Level::DEBUG, "Just ticking time".to_string()))?;

    // Check that the multisig accounts registry has been generated
    let multisig_accounts_registry_id = multisig_accounts_registry_of(&kingdom);
    let _trigger = test_client
        .query(FindTriggers::new())
        .filter_with(|trigger| trigger.id.eq(multisig_accounts_registry_id.clone()))
        .execute_single()
        .expect("multisig accounts registry should be generated after domain creation");

    // Populate residents in the domain
    let mut residents = core::iter::repeat_with(|| gen_account_in(&kingdom))
        .take(1 + N_SIGNATORIES)
        .collect::<BTreeMap<AccountId, KeyPair>>();
    alt_client((BOB_ID.clone(), BOB_KEYPAIR.clone()), &test_client).submit_all_blocking(
        residents
            .keys()
            .cloned()
            .map(Account::new)
            .map(Register::account),
    )?;

    // Create a multisig account ID and discard the corresponding private key
    // FIXME #5022 Should not allow arbitrary IDs. Otherwise, after #4426 pre-registration account will be hijacked as a multisig account
    let multisig_account_id = gen_account_in(&kingdom).0;

    let not_signatory = residents.pop_first().unwrap();
    let mut signatories = residents;

    let args = &MultisigAccountArgs {
        account: multisig_account_id.signatory().clone(),
        signatories: signatories
            .keys()
            .enumerate()
            .map(|(weight, id)| (id.clone(), 1 + weight as u8))
            .collect(),
        // Can be met without the first signatory
        quorum: (1..=N_SIGNATORIES).skip(1).sum::<usize>() as u16,
        transaction_ttl_ms: transaction_ttl_ms.unwrap_or(u64::MAX),
    };
    let register_multisig_account =
        ExecuteTrigger::new(multisig_accounts_registry_id).with_args(args);

    // Any account in another domain cannot register a multisig account without special permission
    let _err = alt_client(
        (CARPENTER_ID.clone(), CARPENTER_KEYPAIR.clone()),
        &test_client,
    )
    .submit_blocking(register_multisig_account.clone())
    .expect_err("multisig account should not be registered by account of another domain");

    // Any account in the same domain can register a multisig account without special permission
    alt_client(not_signatory, &test_client)
        .submit_blocking(register_multisig_account)
        .expect("multisig account should be registered by account of the same domain");

    // Check that the multisig account has been registered
    test_client
        .query(client::account::all())
        .filter_with(|account| account.id.eq(multisig_account_id.clone()))
        .execute_single()
        .expect("multisig account should be created by calling the multisig accounts registry");

    // Check that the multisig transactions registry has been generated
    let multisig_transactions_registry_id = multisig_transactions_registry_of(&multisig_account_id);
    let _trigger = test_client
        .query(FindTriggers::new())
        .filter_with(|trigger| trigger.id.eq(multisig_transactions_registry_id.clone()))
        .execute_single()
        .expect("multisig transactions registry should be generated along with the corresponding multisig account");

    let key: Name = "key".parse().unwrap();
    let instructions = vec![SetKeyValue::account(
        multisig_account_id.clone(),
        key.clone(),
        "value".parse::<Json>().unwrap(),
    )
    .into()];
    let instructions_hash = HashOf::new(&instructions);

    let proposer = signatories.pop_last().unwrap();
    let approvers = signatories;

    let args = &MultisigTransactionArgs::Propose(instructions);
    let propose = ExecuteTrigger::new(multisig_transactions_registry_id.clone()).with_args(args);

    alt_client(proposer, &test_client).submit_blocking(propose)?;

    // Check that the multisig transaction has not yet executed
    let _err = test_client
        .query_single(FindAccountMetadata::new(
            multisig_account_id.clone(),
            key.clone(),
        ))
        .expect_err("key-value shouldn't be set without enough approvals");

    // Allow time to elapse to test the expiration
    if let Some(ms) = transaction_ttl_ms {
        std::thread::sleep(Duration::from_millis(ms))
    };
    test_client.submit_blocking(Log::new(Level::DEBUG, "Just ticking time".to_string()))?;

    // All but the first signatory approve the multisig transaction
    for approver in approvers.into_iter().skip(1) {
        let args = &MultisigTransactionArgs::Approve(instructions_hash);
        let approve =
            ExecuteTrigger::new(multisig_transactions_registry_id.clone()).with_args(args);

        alt_client(approver, &test_client).submit_blocking(approve)?;
    }
    // Check that the multisig transaction has executed
    let res = test_client.query_single(FindAccountMetadata::new(
        multisig_account_id.clone(),
        key.clone(),
    ));

    if transaction_ttl_ms.is_some() {
        let _err = res.expect_err("key-value shouldn't be set despite enough approvals");
    } else {
        res.expect("key-value should be set with enough approvals");
    }

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
#[test]
#[allow(clippy::similar_names, clippy::too_many_lines)]
fn multisig_recursion() -> Result<()> {
    let (network, _rt) = NetworkBuilder::new().start_blocking()?;
    let test_client = network.client();

    let wonderland = "wonderland";
    let ms_accounts_registry_id = multisig_accounts_registry_of(&wonderland.parse().unwrap());

    // Populate signatories in the domain
    let signatories = core::iter::repeat_with(|| gen_account_in(wonderland))
        .take(6)
        .collect::<BTreeMap<AccountId, KeyPair>>();
    test_client.submit_all_blocking(
        signatories
            .keys()
            .cloned()
            .map(Account::new)
            .map(Register::account),
    )?;

    // Recursively register multisig accounts from personal signatories to the root one
    let mut sigs = signatories.clone();
    let sigs_345 = sigs.split_off(signatories.keys().nth(3).unwrap());
    let sigs_12 = sigs.split_off(signatories.keys().nth(1).unwrap());
    let mut sigs_0 = sigs;

    let register_ms_accounts = |sigs_list: Vec<Vec<&AccountId>>| {
        sigs_list
            .into_iter()
            .map(|sigs| {
                let ms_account_id = gen_account_in(wonderland).0;
                let args = MultisigAccountArgs {
                    account: ms_account_id.signatory().clone(),
                    signatories: sigs.iter().copied().map(|id| (id.clone(), 1)).collect(),
                    quorum: sigs.len().try_into().unwrap(),
                    transaction_ttl_ms: u64::MAX,
                };
                let register_ms_account =
                    ExecuteTrigger::new(ms_accounts_registry_id.clone()).with_args(&args);

                test_client
                    .submit_blocking(register_ms_account)
                    .expect("multisig account should be registered by account of the same domain");

                ms_account_id
            })
            .collect::<Vec<AccountId>>()
    };

    let sigs_list: Vec<Vec<&AccountId>> = [&sigs_12, &sigs_345]
        .into_iter()
        .map(|sigs| sigs.keys().collect())
        .collect();
    let msas = register_ms_accounts(sigs_list);
    let msa_12 = msas[0].clone();
    let msa_345 = msas[1].clone();

    let sigs_list = vec![vec![&msa_12, &msa_345]];
    let msas = register_ms_accounts(sigs_list);
    let msa_12345 = msas[0].clone();

    let sig_0 = sigs_0.keys().next().unwrap().clone();
    let sigs_list = vec![vec![&sig_0, &msa_12345]];
    let msas = register_ms_accounts(sigs_list);
    // The root multisig account with 6 personal signatories under its umbrella
    let msa_012345 = msas[0].clone();

    // One of personal signatories proposes a multisig transaction
    let key: Name = "key".parse().unwrap();
    let instructions = vec![SetKeyValue::account(
        msa_012345.clone(),
        key.clone(),
        "value".parse::<Json>().unwrap(),
    )
    .into()];
    let instructions_hash = HashOf::new(&instructions);

    let proposer = sigs_0.pop_last().unwrap();
    let ms_transactions_registry_id = multisig_transactions_registry_of(&msa_012345);
    let args = MultisigTransactionArgs::Propose(instructions);
    let propose = ExecuteTrigger::new(ms_transactions_registry_id.clone()).with_args(&args);

    alt_client(proposer, &test_client).submit_blocking(propose)?;

    // Ticks as many times as the multisig recursion
    (0..2).for_each(|_| {
        test_client
            .submit_blocking(Log::new(Level::DEBUG, "Just ticking time".to_string()))
            .unwrap();
    });

    // Check that the entire authentication policy has been deployed down to one of the leaf registries
    let approval_hash_to_12345 = {
        let approval_hash_to_012345 = {
            let registry_id = multisig_transactions_registry_of(&msa_012345);
            let args = MultisigTransactionArgs::Approve(instructions_hash);
            let approve: InstructionBox = ExecuteTrigger::new(registry_id.clone())
                .with_args(&args)
                .into();

            HashOf::new(&vec![approve])
        };
        let registry_id = multisig_transactions_registry_of(&msa_12345);
        let args = MultisigTransactionArgs::Approve(approval_hash_to_012345);
        let approve: InstructionBox = ExecuteTrigger::new(registry_id.clone())
            .with_args(&args)
            .into();

        HashOf::new(&vec![approve])
    };

    let approvals_at_12: BTreeSet<AccountId> = test_client
        .query_single(FindTriggerMetadata::new(
            multisig_transactions_registry_of(&msa_12),
            format!("proposals/{approval_hash_to_12345}/approvals")
                .parse()
                .unwrap(),
        ))
        .expect("leaf approvals should be initialized by the root proposal")
        .try_into_any()
        .unwrap();

    assert!(1 == approvals_at_12.len() && approvals_at_12.contains(&msa_12345));

    // Check that the multisig transaction has not yet executed
    let _err = test_client
        .query_single(FindAccountMetadata::new(msa_012345.clone(), key.clone()))
        .expect_err("key-value shouldn't be set without enough approvals");

    // All the rest signatories approve the multisig transaction
    let approve_for_each = |approvers: BTreeMap<AccountId, KeyPair>,
                            instructions_hash: HashOf<Vec<InstructionBox>>,
                            ms_account: &AccountId| {
        for approver in approvers {
            let registry_id = multisig_transactions_registry_of(ms_account);
            let args = MultisigTransactionArgs::Approve(instructions_hash);
            let approve = ExecuteTrigger::new(registry_id.clone()).with_args(&args);

            alt_client(approver, &test_client)
                .submit_blocking(approve)
                .expect("should successfully approve the proposal");
        }
    };

    approve_for_each(sigs_12, approval_hash_to_12345, &msa_12);
    approve_for_each(sigs_345, approval_hash_to_12345, &msa_345);

    // Let the intermediate registry (12345) collect approvals and approve the original proposal
    test_client.submit_blocking(Log::new(Level::DEBUG, "Just ticking time".to_string()))?;

    // Let the root registry (012345) collect approvals and execute the original proposal
    test_client.submit_blocking(Log::new(Level::DEBUG, "Just ticking time".to_string()))?;

    // Check that the multisig transaction has executed
    test_client
        .query_single(FindAccountMetadata::new(msa_012345.clone(), key.clone()))
        .expect("key-value should be set with enough approvals");

    Ok(())
}

#[test]
fn persistent_domain_level_authority() -> Result<()> {
    let (network, _rt) = NetworkBuilder::new().start_blocking()?;
    let test_client = network.client();

    let wonderland: DomainId = "wonderland".parse().unwrap();

    let ms_accounts_registry_id = multisig_accounts_registry_of(&wonderland);

    // Domain owner changes from Alice to Bob
    test_client.submit_blocking(Transfer::domain(
        ALICE_ID.clone(),
        wonderland,
        BOB_ID.clone(),
    ))?;

    // One block gap to follow the domain owner change
    test_client.submit_blocking(Log::new(Level::DEBUG, "Just ticking time".to_string()))?;

    // Bob is the authority of the wonderland multisig accounts registry
    let ms_accounts_registry = test_client
        .query(FindTriggers::new())
        .filter_with(|trigger| trigger.id.eq(ms_accounts_registry_id.clone()))
        .execute_single()
        .expect("multisig accounts registry should survive before and after a domain owner change");

    assert!(*ms_accounts_registry.action().authority() == BOB_ID.clone());

    Ok(())
}

#[test]
fn reserved_names() {
    let (network, _rt) = NetworkBuilder::new().start_blocking().unwrap();
    let test_client = network.client();

    let account_in_another_domain = gen_account_in("garden_of_live_flowers").0;

    {
        let reserved_prefix = "multisig_accounts_";
        let register = {
            let id: TriggerId = format!("{reserved_prefix}{}", account_in_another_domain.domain())
                .parse()
                .unwrap();
            let action = Action::new(
                Vec::<InstructionBox>::new(),
                Repeats::Indefinitely,
                ALICE_ID.clone(),
                ExecuteTriggerEventFilter::new(),
            );
            Register::trigger(Trigger::new(id, action))
        };
        let _err = test_client.submit_blocking(register).expect_err(
            "trigger with this name shouldn't be registered by anyone other than multisig system",
        );
    }

    {
        let reserved_prefix = "multisig_transactions_";
        let register = {
            let id: TriggerId = format!(
                "{reserved_prefix}{}_{}",
                account_in_another_domain.signatory(),
                account_in_another_domain.domain()
            )
            .parse()
            .unwrap();
            let action = Action::new(
                Vec::<InstructionBox>::new(),
                Repeats::Indefinitely,
                ALICE_ID.clone(),
                ExecuteTriggerEventFilter::new(),
            );
            Register::trigger(Trigger::new(id, action))
        };
        let _err = test_client.submit_blocking(register).expect_err(
            "trigger with this name shouldn't be registered by anyone other than domain owner",
        );
    }

    {
        let reserved_prefix = "multisig_signatory_";
        let register = {
            let id: RoleId = format!(
                "{reserved_prefix}{}_{}",
                account_in_another_domain.signatory(),
                account_in_another_domain.domain()
            )
            .parse()
            .unwrap();
            Register::role(Role::new(id, ALICE_ID.clone()))
        };
        let _err = test_client.submit_blocking(register).expect_err(
            "role with this name shouldn't be registered by anyone other than domain owner",
        );
    }
}

fn alt_client(signatory: (AccountId, KeyPair), base_client: &client::Client) -> client::Client {
    client::Client {
        account: signatory.0,
        key_pair: signatory.1,
        ..base_client.clone()
    }
}

fn multisig_accounts_registry_of(domain: &DomainId) -> TriggerId {
    format!("multisig_accounts_{domain}",).parse().unwrap()
}

fn multisig_transactions_registry_of(multisig_account: &AccountId) -> TriggerId {
    format!(
        "multisig_transactions_{}_{}",
        multisig_account.signatory(),
        multisig_account.domain()
    )
    .parse()
    .unwrap()
}

#[allow(dead_code)]
fn debug_mst_registry(msa: &AccountId, client: &client::Client) {
    let mst_registry = client
        .query(FindTriggers::new())
        .filter_with(|trigger| trigger.id.eq(multisig_transactions_registry_of(msa)))
        .execute_single()
        .unwrap();
    let mst_metadata = mst_registry.action().metadata();

    iroha_logger::error!(%msa, ?mst_metadata);
}
