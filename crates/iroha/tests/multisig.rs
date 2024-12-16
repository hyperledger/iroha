use std::{
    collections::BTreeMap,
    num::{NonZeroU16, NonZeroU64},
    time::Duration,
};

use derive_more::Constructor;
use eyre::Result;
use iroha::{
    client::Client,
    crypto::KeyPair,
    data_model::{prelude::*, Level},
    executor_data_model::isi::multisig::*,
};
use iroha_executor_data_model::permission::account::CanRegisterAccount;
use iroha_test_network::*;
use iroha_test_samples::{
    gen_account_in, ALICE_ID, BOB_ID, BOB_KEYPAIR, CARPENTER_ID, CARPENTER_KEYPAIR,
};

#[test]
fn multisig_normal() -> Result<()> {
    multisig_base(TestSuite::normal())
}

#[test]
fn multisig_unauthorized() -> Result<()> {
    multisig_base(TestSuite::unauthorized())
}

#[test]
fn multisig_expires() -> Result<()> {
    multisig_base(TestSuite::expires())
}

#[test]
fn multisig_recursion_normal() -> Result<()> {
    multisig_recursion_base(TestSuite::normal())
}

#[test]
fn multisig_recursion_unauthorized() -> Result<()> {
    multisig_recursion_base(TestSuite::unauthorized())
}

#[test]
fn multisig_recursion_expires() -> Result<()> {
    multisig_recursion_base(TestSuite::expires())
}

#[derive(Constructor)]
struct TestSuite {
    domain: DomainId,
    multisig_account_id: AccountId,
    unauthorized_target_opt: Option<AccountId>,
    transaction_ttl_ms_opt: Option<u64>,
}

impl TestSuite {
    fn normal() -> Self {
        // New domain for this test
        let domain = "kingdom".parse().unwrap();
        // Create a multisig account ID and discard the corresponding private key
        // FIXME #5022 refuse user input to prevent multisig monopoly and pre-registration hijacking
        let multisig_account_id = gen_account_in(&domain).0;
        // Make some changes to the multisig account itself
        let unauthorized_target_opt = None;
        // Semi-permanently valid
        let transaction_ttl_ms_opt = None;

        Self::new(
            domain,
            multisig_account_id,
            unauthorized_target_opt,
            transaction_ttl_ms_opt,
        )
    }

    fn unauthorized() -> Self {
        let domain = "kingdom".parse().unwrap();
        let multisig_account_id = gen_account_in(&domain).0;
        // Someone that the multisig account has no permission to access
        let unauthorized_target_opt = Some(ALICE_ID.clone());

        Self::new(domain, multisig_account_id, unauthorized_target_opt, None)
    }

    fn expires() -> Self {
        let domain = "kingdom".parse().unwrap();
        let multisig_account_id = gen_account_in(&domain).0;
        // Expires after 1 sec
        let transaction_ttl_ms_opt = Some(1_000);

        Self::new(domain, multisig_account_id, None, transaction_ttl_ms_opt)
    }
}

/// # Scenario
///
/// 1. Signatories are populated and ready to join a multisig account
/// 2. Someone in the domain registers a multisig account
/// 3. One of the signatories of the multisig account proposes a multisig transaction
/// 4. Other signatories approve the multisig transaction
/// 5. The multisig transaction executes when all of the following are met:
///     - Quorum reached: authenticated
///     - Transaction has not expired
///     - Every instruction validated against the multisig account: authorized
/// 6. Either execution or expiration on approval deletes the transaction entry
#[expect(clippy::cast_possible_truncation, clippy::too_many_lines)]
fn multisig_base(suite: TestSuite) -> Result<()> {
    const N_SIGNATORIES: usize = 5;

    let TestSuite {
        domain,
        multisig_account_id,
        unauthorized_target_opt,
        transaction_ttl_ms_opt,
    } = suite;

    let (network, _rt) = NetworkBuilder::new().start_blocking()?;
    let test_client = network.client();

    // Assume some domain registered after genesis
    let register_and_transfer_kingdom: [InstructionBox; 2] = [
        Register::domain(Domain::new(domain.clone())).into(),
        Transfer::domain(ALICE_ID.clone(), domain.clone(), BOB_ID.clone()).into(),
    ];
    test_client.submit_all_blocking(register_and_transfer_kingdom)?;

    // Populate residents in the domain
    let mut residents = core::iter::repeat_with(|| gen_account_in(&domain))
        .take(1 + N_SIGNATORIES)
        .collect::<BTreeMap<AccountId, KeyPair>>();
    alt_client((BOB_ID.clone(), BOB_KEYPAIR.clone()), &test_client).submit_all_blocking(
        residents
            .keys()
            .cloned()
            .map(Account::new)
            .map(Register::account),
    )?;

    let non_signatory = residents.pop_first().unwrap();
    let mut signatories = residents;

    let register_multisig_account = MultisigRegister::new(
        multisig_account_id.clone(),
        MultisigSpec::new(
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
        ),
    );

    // Any account in another domain cannot register a multisig account without special permission
    let _err = alt_client(
        (CARPENTER_ID.clone(), CARPENTER_KEYPAIR.clone()),
        &test_client,
    )
    .submit_blocking(register_multisig_account.clone())
    .expect_err("multisig account should not be registered by account of another domain");

    // Non-signatory account in the same domain cannot register a multisig account without special permission
    let _err = alt_client(non_signatory.clone(), &test_client)
        .submit_blocking(register_multisig_account.clone())
        .expect_err(
            "multisig account should not be registered by non-signatory account of the same domain",
        );

    // All but the first signatory approve the proposal
    let signatory = signatories.pop_first().unwrap();

    // Signatory account cannot register a multisig account without special permission
    let _err = alt_client(signatory, &test_client)
        .submit_blocking(register_multisig_account.clone())
        .expect_err("multisig account should not be registered by signatory account");

    // Account with permission can register a multisig account
    alt_client((BOB_ID.clone(), BOB_KEYPAIR.clone()), &test_client).submit_blocking(
        Grant::account_permission(CanRegisterAccount { domain }, non_signatory.0.clone()),
    )?;
    alt_client(non_signatory, &test_client)
        .submit_blocking(register_multisig_account)
        .expect("multisig account should be registered by account with permission");

    // Check that the multisig account has been registered
    test_client
        .query(FindAccounts::new())
        .filter_with(|account| account.id.eq(multisig_account_id.clone()))
        .execute_single()
        .expect("multisig account should be created");

    let key: Name = "success_marker".parse().unwrap();
    let transaction_target = unauthorized_target_opt
        .as_ref()
        .unwrap_or(&multisig_account_id)
        .clone();
    let instructions = vec![SetKeyValue::account(
        transaction_target.clone(),
        key.clone(),
        "congratulations".parse::<Json>().unwrap(),
    )
    .into()];
    let instructions_hash = HashOf::new(&instructions);

    let proposer = signatories.pop_last().unwrap();
    let mut approvers = signatories.into_iter();

    let propose = MultisigPropose::new(multisig_account_id.clone(), instructions, None);
    alt_client(proposer, &test_client).submit_blocking(propose)?;

    // Allow time to elapse to test the expiration
    if let Some(ms) = transaction_ttl_ms_opt {
        std::thread::sleep(Duration::from_millis(ms))
    };
    test_client.submit_blocking(Log::new(Level::DEBUG, "Just ticking time".to_string()))?;

    let approve = MultisigApprove::new(multisig_account_id.clone(), instructions_hash);

    // Approve once to see if the proposal expires
    let approver = approvers.next().unwrap();
    alt_client(approver, &test_client).submit_blocking(approve.clone())?;

    // Subsequent approvals should succeed unless the proposal is expired
    for _ in 0..(N_SIGNATORIES - 4) {
        let approver = approvers.next().unwrap();
        let res = alt_client(approver, &test_client).submit_blocking(approve.clone());
        match &transaction_ttl_ms_opt {
            None => {
                res.unwrap();
            }
            _ => {
                let _err = res.unwrap_err();
            }
        }
    }

    // Check that the multisig transaction has not yet executed
    let _err = test_client
        .query(FindAccounts)
        .filter_with(|account| account.id.eq(transaction_target.clone()))
        .select_with(|account| account.metadata.key(key.clone()))
        .execute_single()
        .expect_err("instructions shouldn't execute without enough approvals");

    // The last approve to proceed to validate and execute the instructions
    let approver = approvers.next().unwrap();
    let res = alt_client(approver, &test_client).submit_blocking(approve.clone());
    match (&transaction_ttl_ms_opt, &unauthorized_target_opt) {
        (None, None) => {
            res.unwrap();
        }
        _ => {
            let _err = res.unwrap_err();
        }
    }

    // Check if the multisig transaction has executed
    let res = test_client
        .query(FindAccounts)
        .filter_with(|account| account.id.eq(transaction_target.clone()))
        .select_with(|account| account.metadata.key(key.clone()))
        .execute_single();
    match (&transaction_ttl_ms_opt, &unauthorized_target_opt) {
        (None, None) => {
            res.unwrap();
        }
        _ => {
            let _err = res.unwrap_err();
        }
    }

    // Check if the transaction entry is deleted
    let res = test_client
        .query(FindAccounts)
        .filter_with(|account| account.id.eq(multisig_account_id))
        .select_with(|account| {
            account.metadata.key(
                format!("multisig/proposals/{instructions_hash}")
                    .parse()
                    .unwrap(),
            )
        })
        .execute_single();
    match (&transaction_ttl_ms_opt, &unauthorized_target_opt) {
        (None, Some(_)) => {
            // In case failing validation, the entry can exit only by expiring
            res.unwrap();
        }
        _ => {
            let _err = res.unwrap_err();
        }
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
#[expect(clippy::similar_names, clippy::too_many_lines)]
fn multisig_recursion_base(suite: TestSuite) -> Result<()> {
    let TestSuite {
        domain: _,
        multisig_account_id: _,
        unauthorized_target_opt,
        transaction_ttl_ms_opt,
    } = suite;

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
    let sig_0 = sigs.pop_last().unwrap();

    let register_ms_account = |sigs: Vec<&AccountId>| {
        let ms_account_id = gen_account_in(wonderland).0;
        let spec = MultisigSpec::new(
            // Equal votes
            sigs.iter().copied().map(|id| (id.clone(), 1)).collect(),
            // Unanimous
            sigs.len()
                .try_into()
                .ok()
                .and_then(NonZeroU16::new)
                .unwrap(),
            transaction_ttl_ms_opt
                .and_then(NonZeroU64::new)
                .unwrap_or(NonZeroU64::MAX),
        );
        let register = MultisigRegister::new(ms_account_id.clone(), spec.clone());

        test_client
            .submit_blocking(register)
            .expect("the domain owner should succeed to register a multisig account");

        (ms_account_id, spec)
    };

    let (msa_12, _spec_12) = register_ms_account(sigs_12.keys().collect());
    let (msa_345, _spec_345) = register_ms_account(sigs_345.keys().collect());
    let (msa_12345, _spec_12345) = register_ms_account(vec![&msa_12, &msa_345]);
    // The root multisig account with 6 personal signatories under its umbrella
    let (msa_012345, _spec_012345) = register_ms_account(vec![&sig_0.0, &msa_12345]);

    // One of personal signatories proposes a multisig transaction
    let key: Name = "success_marker".parse().unwrap();
    let transaction_target = unauthorized_target_opt
        .as_ref()
        .unwrap_or(&msa_012345)
        .clone();
    let instructions = vec![SetKeyValue::account(
        transaction_target.clone(),
        key.clone(),
        "congratulations".parse::<Json>().unwrap(),
    )
    .into()];
    let instructions_hash = HashOf::new(&instructions);

    let proposer = sig_0;
    let propose = MultisigPropose::new(msa_012345.clone(), instructions, None);

    alt_client(proposer, &test_client).submit_blocking(propose)?;

    // Allow time to elapse to test the expiration
    if let Some(ms) = transaction_ttl_ms_opt {
        std::thread::sleep(Duration::from_millis(ms))
    };
    test_client.submit_blocking(Log::new(Level::DEBUG, "Just ticking time".to_string()))?;

    // Check that the entire authentication policy has been deployed down to one of the leaf signatories
    let approve_to_012345: InstructionBox =
        MultisigApprove::new(msa_012345.clone(), instructions_hash).into();
    let approval_hash_to_012345 = HashOf::new(&vec![approve_to_012345]);

    let approve_to_12345: InstructionBox =
        MultisigApprove::new(msa_12345.clone(), approval_hash_to_012345).into();
    let approval_hash_to_12345 = HashOf::new(&vec![approve_to_12345.clone()]);

    let proposal_value_at = |msa: AccountId, mst_hash: HashOf<Vec<InstructionBox>>| {
        test_client
            .query(FindAccounts)
            .filter_with(|account| account.id.eq(msa.clone()))
            .select_with(|account| {
                account
                    .metadata
                    .key(format!("multisig/proposals/{mst_hash}").parse().unwrap())
            })
            .execute_single()
            .expect("should be initialized by the root proposal")
            .try_into_any::<MultisigProposalValue>()
            .unwrap()
    };
    let proposal_value_at_012345 = proposal_value_at(msa_012345.clone(), instructions_hash);
    let proposal_value_at_12 = proposal_value_at(msa_12.clone(), approval_hash_to_12345);

    assert_eq!(proposal_value_at_12.instructions, vec![approve_to_12345]);
    assert_eq!(
        proposal_value_at_12.proposed_at_ms,
        proposal_value_at_012345.proposed_at_ms
    );
    assert_eq!(
        proposal_value_at_12.expires_at_ms,
        proposal_value_at_012345.expires_at_ms
    );
    assert!(proposal_value_at_12.approvals.is_empty());
    assert_eq!(proposal_value_at_12.is_relayed, Some(false));

    // All the rest signatories try to approve the multisig transaction
    let mut approvals_iter = sigs_12
        .into_iter()
        .map(|sig| (sig, msa_12.clone()))
        .chain(sigs_345.into_iter().map(|sig| (sig, msa_345.clone())))
        .map(|(sig, msa)| (sig, MultisigApprove::new(msa, approval_hash_to_12345)));

    // Approve once to see if the proposal expires
    let (approver, approve) = approvals_iter.next().unwrap();
    alt_client(approver, &test_client).submit_blocking(approve)?;

    // Subsequent approvals should succeed unless the proposal is expired
    for _ in 2..=4 {
        let (approver, approve) = approvals_iter.next().unwrap();
        let res = alt_client(approver, &test_client).submit_blocking(approve.clone());
        match &transaction_ttl_ms_opt {
            None => {
                res.unwrap();
            }
            _ => {
                let _err = res.unwrap_err();
            }
        }
    }

    // Check that the multisig transaction has not yet executed
    let _err = test_client
        .query(FindAccounts)
        .filter_with(|account| account.id.eq(transaction_target.clone()))
        .select_with(|account| account.metadata.key(key.clone()))
        .execute_single()
        .expect_err("instructions shouldn't execute without enough approvals");

    // The last approve to proceed to validate and execute the instructions
    let (approver, approve) = approvals_iter.next().unwrap();
    let res = alt_client(approver, &test_client).submit_blocking(approve.clone());
    match (&transaction_ttl_ms_opt, &unauthorized_target_opt) {
        (None, None) => {
            res.unwrap();
        }
        _ => {
            let _err = res.unwrap_err();
        }
    }

    // Check if the multisig transaction has executed
    let res = test_client
        .query(FindAccounts)
        .filter_with(|account| account.id.eq(transaction_target))
        .select_with(|account| account.metadata.key(key.clone()))
        .execute_single();
    match (&transaction_ttl_ms_opt, &unauthorized_target_opt) {
        (None, None) => {
            res.unwrap();
        }
        _ => {
            let _err = res.unwrap_err();
        }
    }

    // Check if the transaction entries are deleted
    for (msa, mst_hash) in [
        (msa_12, approval_hash_to_12345),
        (msa_345, approval_hash_to_12345),
        (msa_12345, approval_hash_to_012345),
        (msa_012345, instructions_hash),
    ] {
        let res = test_client
            .query(FindAccounts)
            .filter_with(|account| account.id.eq(msa))
            .select_with(|account| {
                account
                    .metadata
                    .key(format!("multisig/proposals/{mst_hash}").parse().unwrap())
            })
            .execute_single();
        match (&transaction_ttl_ms_opt, &unauthorized_target_opt) {
            (None, Some(_)) => {
                // In case the root proposal is failing validation, the relevant entries can exit only by expiring
                res.unwrap();
            }
            _ => {
                let _err = res.unwrap_err();
            }
        }
    }

    Ok(())
}

#[test]
fn reserved_roles() {
    let (network, _rt) = NetworkBuilder::new().start_blocking().unwrap();
    let test_client = network.client();

    let account_in_another_domain = gen_account_in("garden_of_live_flowers").0;
    let register = {
        let role = format!(
            "MULTISIG_SIGNATORY/{}/{}",
            account_in_another_domain.domain(),
            account_in_another_domain.signatory()
        )
        .parse()
        .unwrap();
        Register::role(Role::new(role, ALICE_ID.clone()))
    };

    let _err = test_client.submit_blocking(register).expect_err(
        "role with this name shouldn't be registered by anyone other than the domain owner",
    );
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

    eprintln!("{account:#?}");
}
