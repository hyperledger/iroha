// Same-scope regression coverage extracted to keep the parent source budget bounded.
#[test]
fn xor_quantity_ratio_is_exact_checked_and_rounds_at_nano_boundaries() {
    let zero = Quantity::zero();
    let one_nano = xor_quantity_nanos(1);
    let two_nanos = xor_quantity_nanos(2);
    assert_eq!(
        round_xor_quantity_ratio(&xor_quantity_nanos(8), 5_000, 10_000)
            .expect("bounded exact ratio"),
        xor_quantity_nanos(4)
    );
    assert_eq!(
        round_xor_quantity_ratio(&one_nano, 1, 2).expect("half nano rounds away from zero"),
        one_nano
    );
    assert_eq!(
        round_xor_quantity_ratio(&two_nanos, 1, 3)
            .expect("sub-nano result rounds to the XOR scale"),
        xor_quantity_nanos(1)
    );
    assert_eq!(
        round_xor_quantity_ratio(&xor_quantity_nanos(1), 1, 3)
            .expect("sub-half-nano result rounds to zero"),
        zero
    );
    assert_eq!(
        round_xor_quantity_ratio(&Quantity::zero(), u128::MAX, 1)
            .expect("zero remains zero for any bounded multiplier"),
        Quantity::zero()
    );
    let fractional: Quantity = "1.234567891"
        .parse()
        .expect("canonical fractional Quantity");
    assert_eq!(
        round_xor_quantity_ratio(&fractional, 1, 2).expect("bounded fractional ratio"),
        "0.617283946"
            .parse::<Quantity>()
            .expect("canonical rounded Quantity")
    );
    assert_eq!(
        round_xor_quantity_ratio(&xor_quantity_nanos(1), 1, 0),
        Err(NumericOperationError::DivisionByZero)
    );
    assert_eq!(
        xor_quantity_nanos(1).checked_sub(&xor_quantity_nanos(2)),
        Err(NumericOperationError::QuantityUnderflow)
    );
    assert_eq!(
        round_xor_quantity_ratio(&max_positive_quantity(), 2, 1),
        Err(NumericOperationError::MantissaOverflow)
    );
}
#[test]
fn integer_ratio_helper_rejects_invalid_or_overflowing_economic_inputs() {
    assert_eq!(checked_mul_div_round_u128(5, 1, 2), Ok(3));
    assert_eq!(
        checked_mul_div_round_u128(1, 1, 0),
        Err(PricingComputationError::DivisionByZero(
            "u128 multiply/divide"
        ))
    );
    assert_eq!(
        checked_mul_div_round_u128(u128::MAX, 2, 1),
        Err(PricingComputationError::ArithmeticOverflow(
            "u128 multiply/divide"
        ))
    );
}
#[test]
fn checked_keypair_helpers_preserve_requested_algorithm() {
    assert_eq!(checked_keypair().algorithm(), Algorithm::default());
    assert_eq!(checked_ed25519_keypair().algorithm(), Algorithm::Ed25519);
}
fn block_header_at_epoch(epoch: u64) -> iroha_data_model::block::BlockHeader {
    iroha_data_model::block::BlockHeader::new(
        nonzero!(1_u64),
        None,
        None,
        epoch
            .checked_mul(1_000)
            .expect("test consensus epoch must fit milliseconds"),
        0,
    )
}
pub(super) fn block_header() -> iroha_data_model::block::BlockHeader {
    block_header_at_epoch(5)
}
fn capacity_dispute_block_header() -> iroha_data_model::block::BlockHeader {
    iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 1_700_000_128_000, 0)
}
fn activate_reputation_policy(
    stx: &mut StateTransaction<'_, '_>,
    authority: &AccountId,
) -> [u8; 32] {
    let policy = ReputationJournalAuthorityPolicyV1 {
        version: REPUTATION_JOURNAL_AUTHORITY_POLICY_VERSION_V1,
        revision: 1,
        predecessor_policy_digest: None,
        por_recorder_authority: authority.clone(),
        dispute_recorder_authority: authority.clone(),
        token_recorder_authority: authority.clone(),
        stream_token_delivery: iroha_data_model::sorafs::reputation::stream_token_delivery::StreamTokenReputationDeliveryTemplateV1::default(),
        max_source_age_ms: 24 * 60 * 60 * 1_000,
    };
    let digest = policy.canonical_digest().expect("reputation policy digest");
    // This dispute/repair fixture is an isolated World overlay, not signed policy execution.
    crate::smartcontracts::isi::sorafs_reputation::tests::seed_policy_preimage(
        stx, authority, policy,
    )
    .expect("seed private dispute policy preimage");
    digest
}
fn repair_block_header(height: u64, creation_time_ms: u64) -> iroha_data_model::block::BlockHeader {
    iroha_data_model::block::BlockHeader::new(
        std::num::NonZeroU64::new(height).expect("non-zero test block height"),
        None,
        None,
        creation_time_ms,
        0,
    )
}
fn transact_repair(
    state: &mut State,
    height: u64,
    creation_time_ms: u64,
    operation: impl FnOnce(
        &mut crate::state::StateTransaction<'_, '_>,
    ) -> Result<(), InstructionExecutionError>,
) -> Result<(), InstructionExecutionError> {
    let header = repair_block_header(height, creation_time_ms);
    let block_hash = iroha_crypto::HashOf::new(&header);
    let mut block = state.block(header);
    let mut transaction = block.transaction();
    operation(&mut transaction)?;
    transaction.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit repair test block");
    state.push_block_hash_for_testing(block_hash);
    Ok(())
}
fn committed_repair_fixture(
    ticket_id: &str,
    source_identity: [u8; 32],
    mutate: impl FnOnce(
        &RepairReportV1,
        &mut crate::state::StateTransaction<'_, '_>,
    ) -> Result<(), InstructionExecutionError>,
) -> State {
    let mut state = make_state();
    let provider = ProviderId::new([0xF1; 32]);
    grant_repair_operator(&mut state, &alice(), provider);
    let report = repair_report(ticket_id, provider, [0xF2; 32], &alice(), 4_000);
    transact_repair(&mut state, 1, 4_000_000, |transaction| {
        SubmitSorafsRepairTask::new(
            source_identity,
            to_bytes(&report).expect("encode repair fixture report"),
        )
        .execute(&alice(), transaction)?;
        mutate(&report, transaction)
    })
    .expect("commit repair fixture");
    state
}
