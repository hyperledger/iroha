// P.3: the ledger's capacity, identity and transaction boundaries remain observable
// when a test-only faulty verifier supplies an arbitrary allocation record. These
// controls do not establish FASTPQ soundness or authenticate the synthetic claim.

fn fee_sponsor_faulty_effect_fixture() -> (State, VerifiedFeeSponsorVaultAllocation) {
    use iroha_data_model::nexus::{
        FeeSponsorProgram, FeeSponsorProgramId, FeeSponsorProgramLifecycle, FeeSponsorVault,
        FeeSponsorVaultKey,
    };
    let program_id = FeeSponsorProgramId::new(
        ALICE_ID.clone(),
        "faulty-verifier-capacity".parse().expect("program name"),
    );
    let definition: AssetDefinitionId = "66owaQmAQMuHxPzxUN3bqZ6FJfDa"
        .parse()
        .expect("canonical fee asset");
    let record = fee_sponsor_relay_allocation_fixture(
        program_id.clone(),
        definition.clone(),
        Quantity::from(6_u32),
        DataSpaceId::new(1),
        Hash::new(b"faulty-verifier-first-lease"),
        10,
    );
    let mut world = World::default();
    let mut program = FeeSponsorProgram::new(program_id.clone(), ALICE_ID.clone());
    program.lifecycle = FeeSponsorProgramLifecycle::Active;
    program.active_revision = Some(1);
    world
        .fee_sponsor_programs
        .insert(program_id.clone(), program);
    let key = FeeSponsorVaultKey {
        program_id,
        asset_definition_id: definition,
    };
    world.fee_sponsor_vaults.insert(
        key.clone(),
        FeeSponsorVault {
            key,
            balance: Quantity::from(10_u32),
        },
    );
    (
        State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        ),
        record,
    )
}

fn fee_sponsor_faulty_effect_rows(
    transaction: &StateTransaction<'_, '_>,
) -> std::collections::BTreeMap<StatePath, Vec<u8>> {
    transaction
        .world
        .smart_contract_state
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

// State initialization seeds authenticated SNS and namespace rows. Preserve every
// original key/value, and add exactly the declared lease row when an effect succeeds.
fn fee_sponsor_expected_rows_with_allocation(
    mut rows: std::collections::BTreeMap<StatePath, Vec<u8>>,
    record: &VerifiedFeeSponsorVaultAllocation,
) -> std::collections::BTreeMap<StatePath, Vec<u8>> {
    let key = super::verified_fee_sponsor_vault_allocation_state_key(
        &record.program_id,
        &record.asset_definition_id,
        &record.lease_id,
    )
    .expect("canonical lease key");
    let encoded = super::encode_verified_fee_sponsor_vault_allocation_state(record)
        .expect("complete canonical allocation record");
    assert!(
        rows.insert(key, encoded).is_none(),
        "a new lease has exactly one new row"
    );
    rows
}

#[test]
fn faulty_verifier_fee_sponsor_capacity_is_exact_and_identical_replay_adds_no_lock() {
    let (state, first) = fee_sponsor_faulty_effect_fixture();
    let mut block = state.block(BlockHeader::new(
        nonzero_ext::nonzero!(1_u64),
        None,
        None,
        0,
        0,
    ));
    let mut transaction = block.transaction();
    let baseline = fee_sponsor_faulty_effect_rows(&transaction);
    super::apply_verified_fee_sponsor_vault_allocation(&mut transaction, first.clone())
        .expect("six units fit the authoritative ten-unit vault");
    let first_rows = fee_sponsor_faulty_effect_rows(&transaction);
    assert_eq!(
        first_rows,
        fee_sponsor_expected_rows_with_allocation(baseline.clone(), &first)
    );
    super::apply_verified_fee_sponsor_vault_allocation(&mut transaction, first.clone())
        .expect("an identical replay is an idempotent no-op");
    assert_eq!(fee_sponsor_faulty_effect_rows(&transaction), first_rows);
    let mut second = first.clone();
    second.lease_id = Hash::new(b"faulty-verifier-second-lease");
    second.source_dataspace_id = DataSpaceId::new(2);
    second.verified_allocation = Quantity::from(4_u32);
    let expected_full = fee_sponsor_expected_rows_with_allocation(first_rows, &second);
    super::apply_verified_fee_sponsor_vault_allocation(&mut transaction, second)
        .expect("the second route may lock exactly the four remaining units");
    assert_eq!(
        super::locked_fee_sponsor_vault_capacity(
            &transaction.world,
            &first.program_id,
            &first.asset_definition_id,
            1,
        )
        .unwrap(),
        Quantity::from(10_u32),
    );
    let full_rows = fee_sponsor_faulty_effect_rows(&transaction);
    let mut excess = first.clone();
    excess.lease_id = Hash::new(b"faulty-verifier-excess-lease");
    excess.source_dataspace_id = DataSpaceId::new(3);
    excess.verified_allocation = Quantity::one();
    let error = super::apply_verified_fee_sponsor_vault_allocation(&mut transaction, excess)
        .expect_err("even accepted verification cannot allocate an eleventh unit");
    assert!(
        matches!(&error, InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(message)) if message.contains("exceed source capacity")),
        "{error:?}"
    );
    assert_eq!(fee_sponsor_faulty_effect_rows(&transaction), full_rows);
    assert_eq!(full_rows, expected_full);
    assert_eq!(full_rows.len(), baseline.len() + 2);
    assert_eq!(
        transaction
            .world
            .fee_sponsor_vaults
            .get(&iroha_data_model::nexus::FeeSponsorVaultKey {
                program_id: first.program_id,
                asset_definition_id: first.asset_definition_id,
            })
            .unwrap()
            .balance,
        Quantity::from(10_u32),
        "allocating spend capacity neither mints nor debits the vault",
    );
}

#[test]
fn faulty_verifier_fee_sponsor_cannot_rebind_a_lease_or_overlap_a_live_route() {
    let (state, first) = fee_sponsor_faulty_effect_fixture();
    let mut block = state.block(BlockHeader::new(
        nonzero_ext::nonzero!(1_u64),
        None,
        None,
        0,
        0,
    ));
    let mut transaction = block.transaction();
    super::apply_verified_fee_sponsor_vault_allocation(&mut transaction, first.clone()).unwrap();
    let before = fee_sponsor_faulty_effect_rows(&transaction);
    let mut same_lease = first.clone();
    same_lease.verified_allocation = Quantity::one();
    let error = super::apply_verified_fee_sponsor_vault_allocation(&mut transaction, same_lease)
        .expect_err("a valid-looking second amount cannot reuse the original lease id");
    assert!(
        matches!(&error, InstructionExecutionError::InvariantViolation(message) if message.contains("already bound to another allocation")),
        "{error:?}"
    );
    let mut same_route = first;
    same_route.lease_id = Hash::new(b"faulty-verifier-overlapping-route");
    same_route.verified_allocation = Quantity::one();
    let error = super::apply_verified_fee_sponsor_vault_allocation(&mut transaction, same_route)
        .expect_err("available capacity does not allow two live leases on one route");
    assert!(
        matches!(&error, InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(message)) if message.contains("already has an unexpired spend lease")),
        "{error:?}"
    );
    assert_eq!(fee_sponsor_faulty_effect_rows(&transaction), before);
}

#[test]
fn faulty_verifier_fee_sponsor_respects_current_height_and_scheduled_revision() {
    let (state, mut record) = fee_sponsor_faulty_effect_fixture();
    let mut block = state.block(BlockHeader::new(
        nonzero_ext::nonzero!(1_u64),
        None,
        None,
        0,
        0,
    ));
    let mut transaction = block.transaction();
    let baseline = fee_sponsor_faulty_effect_rows(&transaction);
    record.verified_at_height = 2;
    let error =
        super::apply_verified_fee_sponsor_vault_allocation(&mut transaction, record.clone())
            .expect_err("a verified record belongs to one execution height");
    assert!(
        matches!(&error, InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(message)) if message.contains("another execution height")),
        "{error:?}"
    );
    record.verified_at_height = 1;
    let mut program = transaction
        .world
        .fee_sponsor_programs
        .get(&record.program_id)
        .unwrap()
        .clone();
    program.scheduled_activation = Some(iroha_data_model::nexus::FeeSponsorProgramActivation {
        revision: 2,
        activate_at_height: 10,
    });
    transaction
        .world
        .fee_sponsor_programs
        .insert(record.program_id.clone(), program);
    let error =
        super::apply_verified_fee_sponsor_vault_allocation(&mut transaction, record.clone())
            .expect_err("a lease must end strictly before scheduled revision activation");
    assert!(
        matches!(&error, InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(message)) if message.contains("must expire before scheduled revision")),
        "{error:?}"
    );
    assert_eq!(fee_sponsor_faulty_effect_rows(&transaction), baseline);
    record.expires_at_height = 9;
    let expected = fee_sponsor_expected_rows_with_allocation(baseline, &record);
    super::apply_verified_fee_sponsor_vault_allocation(&mut transaction, record)
        .expect("the preceding height remains admissible");
    assert_eq!(fee_sponsor_faulty_effect_rows(&transaction), expected);
}

#[test]
fn faulty_verifier_fee_sponsor_failed_batch_discards_earlier_allocation() {
    let (state, first) = fee_sponsor_faulty_effect_fixture();
    let mut block = state.block(BlockHeader::new(
        nonzero_ext::nonzero!(1_u64),
        None,
        None,
        0,
        0,
    ));
    let baseline = fee_sponsor_faulty_effect_rows(&block.transaction());
    let expected_partial = fee_sponsor_expected_rows_with_allocation(baseline.clone(), &first);
    {
        let mut transaction = block.transaction();
        super::apply_verified_fee_sponsor_vault_allocation(&mut transaction, first.clone())
            .unwrap();
        let mut excess = first;
        excess.lease_id = Hash::new(b"faulty-verifier-batch-excess");
        excess.source_dataspace_id = DataSpaceId::new(2);
        excess.verified_allocation = Quantity::from(5_u32);
        let error = super::apply_verified_fee_sponsor_vault_allocation(&mut transaction, excess)
            .expect_err("the second instruction exceeds remaining capacity");
        assert!(
            matches!(&error, InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(message)) if message.contains("exceed source capacity")),
            "{error:?}"
        );
        assert_eq!(
            fee_sponsor_faulty_effect_rows(&transaction),
            expected_partial
        );
        // The failed transaction is dropped, exactly as an unsuccessful instruction batch.
    }
    assert_eq!(
        fee_sponsor_faulty_effect_rows(&block.transaction()),
        baseline
    );
}
