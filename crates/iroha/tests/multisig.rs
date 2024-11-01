use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

use eyre::Result;
use iroha::{
    client::Client,
    crypto::KeyPair,
    data_model::{prelude::*, Level},
    multisig_data_model::*,
};
use iroha_multisig_data_model::approvals_key;
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
/// 1. Signatories are populated and ready to join a multisig account
/// 2. Someone in the domain registers a multisig account
/// 3. One of the signatories of the multisig account proposes a multisig transaction
/// 4. Other signatories approve the multisig transaction
/// 5. When the quorum is met, if it is not expired, the multisig transaction executes
#[expect(clippy::cast_possible_truncation)]
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
    // FIXME #5022 refuse user input to prevent multisig monopoly and pre-registration hijacking
    let multisig_account_id = gen_account_in(&kingdom).0;

    // DEBUG: You could target unauthorized one (e.g. Alice) to fail
    let transaction_target = multisig_account_id.clone();

    let not_signatory = residents.pop_first().unwrap();
    let mut signatories = residents;

    let register_multisig_account = MultisigRegister::new(
        multisig_account_id.clone(),
        signatories
            .keys()
            .enumerate()
            .map(|(weight, id)| (id.clone(), 1 + weight as u8))
            .collect(),
        // Quorum can be reached without the first signatory
        (1..=N_SIGNATORIES).skip(1).sum::<usize>() as u16,
        transaction_ttl_ms.unwrap_or(u64::MAX),
    );

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
        .query(FindAccounts::new())
        .filter_with(|account| account.id.eq(multisig_account_id.clone()))
        .execute_single()
        .expect("multisig account should be created");

    let key: Name = "success_marker".parse().unwrap();
    let instructions = vec![SetKeyValue::account(
        transaction_target.clone(),
        key.clone(),
        "congratulations".parse::<Json>().unwrap(),
    )
    .into()];
    let instructions_hash = HashOf::new(&instructions);

    let proposer = signatories.pop_last().unwrap();
    // All but the first signatory approve the proposal
    let mut approvers = signatories.into_iter().skip(1);

    let propose = MultisigPropose::new(multisig_account_id.clone(), instructions);

    alt_client(proposer, &test_client).submit_blocking(propose)?;

    // Check that the multisig transaction has not yet executed
    let _err = test_client
        .query_single(FindAccountMetadata::new(
            multisig_account_id.clone(),
            key.clone(),
        ))
        .expect_err("instructions shouldn't execute without enough approvals");

    // Allow time to elapse to test the expiration
    if let Some(ms) = transaction_ttl_ms {
        std::thread::sleep(Duration::from_millis(ms))
    };
    test_client.submit_blocking(Log::new(Level::DEBUG, "Just ticking time".to_string()))?;

    let approve = MultisigApprove::new(multisig_account_id.clone(), instructions_hash);

    // Approve once to see if the proposal expires
    let approver = approvers.next().unwrap();
    alt_client(approver, &test_client).submit_blocking(approve.clone())?;

    // Subsequent approvals should succeed unless the proposal is expired
    for approver in approvers {
        match alt_client(approver, &test_client).submit_blocking(approve.clone()) {
            Ok(_hash) => assert!(transaction_ttl_ms.is_none()),
            Err(_err) => assert!(transaction_ttl_ms.is_some()),
        }
    }

    // Check if the multisig transaction has executed
    match test_client.query_single(FindAccountMetadata::new(transaction_target, key.clone())) {
        Ok(_value) => assert!(transaction_ttl_ms.is_none()),
        Err(_err) => assert!(transaction_ttl_ms.is_some()),
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
#[expect(clippy::similar_names)]
fn multisig_recursion() -> Result<()> {
    let (network, _rt) = NetworkBuilder::new().start_blocking()?;
    let test_client = network.client();

    let wonderland = "wonderland";

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
                let register_ms_account = MultisigRegister::new(
                    ms_account_id.clone(),
                    sigs.iter().copied().map(|id| (id.clone(), 1)).collect(),
                    sigs.len().try_into().unwrap(),
                    u64::MAX,
                );

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
    let key: Name = "success_marker".parse().unwrap();
    let instructions = vec![SetKeyValue::account(
        msa_012345.clone(),
        key.clone(),
        "congratulations".parse::<Json>().unwrap(),
    )
    .into()];
    let instructions_hash = HashOf::new(&instructions);

    let proposer = sigs_0.pop_last().unwrap();
    let propose = MultisigPropose::new(msa_012345.clone(), instructions);

    alt_client(proposer, &test_client).submit_blocking(propose)?;

    // Check that the entire authentication policy has been deployed down to one of the leaf signatories
    let approval_hash_to_12345 = {
        let approval_hash_to_012345 = {
            let approve: InstructionBox =
                MultisigApprove::new(msa_012345.clone(), instructions_hash).into();

            HashOf::new(&vec![approve])
        };
        let approve: InstructionBox =
            MultisigApprove::new(msa_12345.clone(), approval_hash_to_012345).into();

        HashOf::new(&vec![approve])
    };

    let approvals_at_12: BTreeSet<AccountId> = test_client
        .query_single(FindAccountMetadata::new(
            msa_12.clone(),
            approvals_key(&approval_hash_to_12345),
        ))
        .expect("leaf approvals should be initialized by the root proposal")
        .try_into_any()
        .unwrap();

    assert!(1 == approvals_at_12.len() && approvals_at_12.contains(&msa_12345));

    // Check that the multisig transaction has not yet executed
    let _err = test_client
        .query_single(FindAccountMetadata::new(msa_012345.clone(), key.clone()))
        .expect_err("instructions shouldn't execute without enough approvals");

    // All the rest signatories approve the multisig transaction
    let approve_for_each = |approvers: BTreeMap<AccountId, KeyPair>,
                            instructions_hash: HashOf<Vec<InstructionBox>>,
                            ms_account: &AccountId| {
        for approver in approvers {
            let approve = MultisigApprove::new(ms_account.clone(), instructions_hash);

            alt_client(approver, &test_client)
                .submit_blocking(approve)
                .expect("should successfully approve the proposal");
        }
    };

    approve_for_each(sigs_12, approval_hash_to_12345, &msa_12);
    approve_for_each(sigs_345, approval_hash_to_12345, &msa_345);

    // Check that the multisig transaction has executed
    test_client
        .query_single(FindAccountMetadata::new(msa_012345.clone(), key.clone()))
        .expect("instructions should execute with enough approvals");

    Ok(())
}

#[test]
fn reserved_names() {
    let (network, _rt) = NetworkBuilder::new().start_blocking().unwrap();
    let test_client = network.client();

    let account_in_another_domain = gen_account_in("garden_of_live_flowers").0;

    {
        let register = {
            let role = multisig_role_for(&account_in_another_domain);
            Register::role(Role::new(role, ALICE_ID.clone()))
        };
        let _err = test_client.submit_blocking(register).expect_err(
            "role with this name shouldn't be registered by anyone other than the domain owner",
        );
    }
}

fn alt_client(signatory: (AccountId, KeyPair), base_client: &Client) -> Client {
    Client {
        account: signatory.0,
        key_pair: signatory.1,
        ..base_client.clone()
    }
}

#[expect(dead_code)]
fn debug_account(account_id: &AccountId, client: &Client) {
    let account = client
        .query(FindAccounts)
        .filter_with(|account| account.id.eq(account_id.clone()))
        .execute_single()
        .unwrap();

    iroha_logger::error!(?account);
}
