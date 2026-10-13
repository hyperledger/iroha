//! Bounded orderbook current-memory helpers and their focused regressions.
use super::*;
use iroha_data_model::account::{AccountController, curve::CurveId};
use sorafs_manifest::orderbook::ORDERBOOK_OWNER_ACCOUNT_MAX_BYTES_V1;
/// Compare one signed-payload owner literal with its authoritative account
/// without populating the process-wide I105 cache or retaining parse scratch.
pub(super) fn owner_literal_matches_for_current(
    owner: &AccountId,
    literal: &[u8],
    current: &mut OrderbookQueryCurrent,
) -> Result<bool, InstructionExecutionError> {
    let resident_bytes = current.resident_bytes();
    let result = owner_literal_matches_inner(owner, literal, current);
    *current =
        OrderbookQueryCurrent::new(resident_bytes).map_err(InstructionExecutionError::Query)?;
    result
}
fn owner_literal_matches_inner(
    owner: &AccountId,
    literal: &[u8],
    current: &mut OrderbookQueryCurrent,
) -> Result<bool, InstructionExecutionError> {
    if literal.len() > ORDERBOOK_OWNER_ACCOUNT_MAX_BYTES_V1 {
        return Ok(false);
    }
    let canonical_len = account_address_len(owner)?;
    // The canonical payload is always encoded by at least one I105 symbol per
    // byte; this cheap lower bound avoids allocating for impossible literals.
    if canonical_len > literal.len() {
        return Ok(false);
    }
    let maximum_digits = canonical_len
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(1))
        .ok_or_else(|| corrupt_state("orderbook owner I105 scratch length overflow"))?;
    let scratch_bytes = canonical_len
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(maximum_digits))
        .ok_or_else(|| corrupt_state("orderbook owner I105 scratch allocation overflow"))?;
    let mut scratch = current
        .vec_with_capacity::<u8>(scratch_bytes)
        .map_err(InstructionExecutionError::Query)?
        .into_vec();
    encode_account_address(owner, &mut scratch, canonical_len)?;
    if scratch.len() != canonical_len {
        return Err(corrupt_state(
            "orderbook owner canonical address length changed during encoding",
        ));
    }
    let checksum = iroha_data_model::account::address::i105_checksum_digits(&scratch);
    let digits_start = encode_base105_in_scratch(&mut scratch, canonical_len, maximum_digits)?;
    let mut numeric_sentinel = [0_u8; 6];
    let sentinel = iroha_data_model::account::address::write_i105_sentinel(
        iroha_data_model::account::address::chain_discriminant(),
        &mut numeric_sentinel,
    );
    let mut remaining = literal;
    if !consume_exact(&mut remaining, sentinel) {
        return Ok(false);
    }
    for digit in scratch[digits_start..].iter().chain(checksum.iter()) {
        if !consume_exact(&mut remaining, i105_symbol(*digit)?.as_bytes()) {
            return Ok(false);
        }
    }
    Ok(remaining.is_empty())
}
fn account_address_len(owner: &AccountId) -> Result<usize, InstructionExecutionError> {
    let controller_bytes = match owner.controller() {
        AccountController::Single(key) => {
            let (_, payload) = key.try_to_bytes().map_err(|error| {
                corrupt_state(format!("invalid orderbook owner public key: {error}"))
            })?;
            if u8::try_from(payload.len()).is_ok() {
                3_usize
            } else {
                u16::try_from(payload.len())
                    .map_err(|_| corrupt_state("orderbook owner public key is too long"))?;
                4_usize
            }
            .checked_add(payload.len())
            .ok_or_else(|| corrupt_state("orderbook owner address length overflow"))?
        }
        AccountController::Multisig(policy) => {
            u16::try_from(policy.members().len())
                .map_err(|_| corrupt_state("orderbook owner has too many multisig members"))?;
            policy.members().iter().try_fold(6_usize, |bytes, member| {
                let (_, payload) = member.public_key().try_to_bytes().map_err(|error| {
                    corrupt_state(format!(
                        "invalid orderbook owner multisig public key: {error}"
                    ))
                })?;
                u16::try_from(payload.len()).map_err(|_| {
                    corrupt_state("orderbook owner multisig public key is too long")
                })?;
                bytes
                    .checked_add(5)
                    .and_then(|bytes| bytes.checked_add(payload.len()))
                    .ok_or_else(|| corrupt_state("orderbook owner address length overflow"))
            })?
        }
    };
    controller_bytes
        .checked_add(1)
        .ok_or_else(|| corrupt_state("orderbook owner address length overflow"))
}
fn encode_account_address(
    owner: &AccountId,
    canonical: &mut Vec<u8>,
    maximum: usize,
) -> Result<(), InstructionExecutionError> {
    match owner.controller() {
        AccountController::Single(key) => {
            push_bounded(canonical, maximum, 0b0000_0010)?;
            let (algorithm, payload) = key.try_to_bytes().map_err(|error| {
                corrupt_state(format!("invalid orderbook owner public key: {error}"))
            })?;
            if let Ok(length) = u8::try_from(payload.len()) {
                for byte in [0, curve_id(algorithm)?, length] {
                    push_bounded(canonical, maximum, byte)?;
                }
            } else {
                let length = u16::try_from(payload.len())
                    .map_err(|_| corrupt_state("orderbook owner public key is too long"))?;
                push_bounded(canonical, maximum, 2)?;
                push_bounded(canonical, maximum, curve_id(algorithm)?)?;
                for byte in length.to_be_bytes() {
                    push_bounded(canonical, maximum, byte)?;
                }
            }
            for &byte in payload {
                push_bounded(canonical, maximum, byte)?;
            }
        }
        AccountController::Multisig(policy) => {
            for byte in [0b0000_1010, 1, policy.version()] {
                push_bounded(canonical, maximum, byte)?;
            }
            for byte in policy.threshold().to_be_bytes() {
                push_bounded(canonical, maximum, byte)?;
            }
            let member_count = u16::try_from(policy.members().len())
                .map_err(|_| corrupt_state("orderbook owner has too many multisig members"))?;
            for byte in member_count.to_be_bytes() {
                push_bounded(canonical, maximum, byte)?;
            }
            for member in policy.members() {
                let (algorithm, payload) = member.public_key().try_to_bytes().map_err(|error| {
                    corrupt_state(format!(
                        "invalid orderbook owner multisig public key: {error}"
                    ))
                })?;
                push_bounded(canonical, maximum, curve_id(algorithm)?)?;
                for byte in member.weight().to_be_bytes() {
                    push_bounded(canonical, maximum, byte)?;
                }
                let length = u16::try_from(payload.len()).map_err(|_| {
                    corrupt_state("orderbook owner multisig public key is too long")
                })?;
                for byte in length.to_be_bytes() {
                    push_bounded(canonical, maximum, byte)?;
                }
                for &byte in payload {
                    push_bounded(canonical, maximum, byte)?;
                }
            }
        }
    }
    Ok(())
}
fn push_bounded(
    bytes: &mut Vec<u8>,
    maximum: usize,
    byte: u8,
) -> Result<(), InstructionExecutionError> {
    if bytes.len() >= maximum {
        return Err(InstructionExecutionError::Query(
            QueryExecutionFail::CapacityLimit,
        ));
    }
    bytes.push(byte);
    Ok(())
}
fn curve_id(algorithm: Algorithm) -> Result<u8, InstructionExecutionError> {
    CurveId::try_from_algorithm(algorithm)
        .map(CurveId::as_u8)
        .map_err(|_| corrupt_state("orderbook owner uses an unsupported account-address curve"))
}
fn encode_base105_in_scratch(
    scratch: &mut Vec<u8>,
    canonical_len: usize,
    maximum_digits: usize,
) -> Result<usize, InstructionExecutionError> {
    if canonical_len == 0 || scratch.len() != canonical_len {
        return Err(corrupt_state("orderbook owner canonical address is empty"));
    }
    let value_end = canonical_len
        .checked_mul(2)
        .ok_or_else(|| corrupt_state("orderbook owner I105 scratch length overflow"))?;
    let maximum = value_end
        .checked_add(maximum_digits)
        .ok_or_else(|| corrupt_state("orderbook owner I105 scratch length overflow"))?;
    if scratch.capacity() < maximum {
        return Err(InstructionExecutionError::Query(
            QueryExecutionFail::CapacityLimit,
        ));
    }
    let leading_zeros = scratch.iter().take_while(|&&byte| byte == 0).count();
    scratch.extend_from_within(..canonical_len);
    let digits_start = value_end;
    let mut start = leading_zeros;
    while start < canonical_len {
        let mut remainder = 0_u32;
        for byte in &mut scratch[canonical_len + start..value_end] {
            let accumulator = (remainder << 8) | u32::from(*byte);
            *byte = u8::try_from(accumulator / 105)
                .expect("base-105 division quotient fits in one byte");
            remainder = accumulator % 105;
        }
        push_bounded(
            scratch,
            maximum,
            u8::try_from(remainder).expect("base-105 remainder fits in one byte"),
        )?;
        while start < canonical_len && scratch[canonical_len + start] == 0 {
            start += 1;
        }
    }
    for _ in 0..leading_zeros {
        push_bounded(scratch, maximum, 0)?;
    }
    if scratch.len() == digits_start {
        push_bounded(scratch, maximum, 0)?;
    }
    scratch[digits_start..].reverse();
    Ok(digits_start)
}
fn i105_symbol(digit: u8) -> Result<&'static str, InstructionExecutionError> {
    iroha_data_model::account::address::i105_symbol(digit)
        .ok_or_else(|| corrupt_state("orderbook owner has an invalid I105 digit"))
}
fn consume_exact(remaining: &mut &[u8], expected: &[u8]) -> bool {
    if !remaining.starts_with(expected) {
        return false;
    }
    *remaining = &remaining[expected.len()..];
    true
}
#[cfg(test)]
pub(super) mod tests {
    use super::super::tests::*;
    use super::*;
    use crate::smartcontracts::isi::query::{
        QueryLimits, SingularQueryOutputLimits, ValidQueryRequest,
    };
    use crate::state::StateReadOnly;
    use iroha_data_model::{
        query::QueryRequest,
        sorafs::orderbook::{
            OrderbookSettlementChannelRecord, OrderbookSettlementIndexRecord,
            OrderbookSettlementRangeRecord, OrderbookTradeRecord,
        },
    };
    use sorafs_manifest::orderbook::{
        ORDERBOOK_PAYLOAD_DECODE_LIMITS_V1, decode_trade_event_v1_with_limits,
    };
    #[test]
    fn receipt_index_bounded_scratch_preserves_order_and_rejects_duplicate_ids() {
        let channel_id = [0x41; 32];
        let duplicate_id = [0x72; 32];
        let mut index = OrderbookSettlementIndexRecord {
            channel_id,
            trade_id: [0x61; 32],
            ranges: vec![
                OrderbookSettlementRangeRecord {
                    receipt_id: duplicate_id,
                    start: 0,
                    end: 10,
                    issued_at_unix: 1,
                },
                OrderbookSettlementRangeRecord {
                    receipt_id: [0x71; 32],
                    start: 10,
                    end: 20,
                    issued_at_unix: 2,
                },
                OrderbookSettlementRangeRecord {
                    receipt_id: [0x73; 32],
                    start: 20,
                    end: 30,
                    issued_at_unix: 3,
                },
            ],
        };
        let before = index.clone();
        validate_receipt_index(&index, channel_id).expect("valid receipt index");
        assert_eq!(index, before);
        index.ranges[2].receipt_id = duplicate_id;
        assert!(matches!(
            validate_receipt_index(&index, channel_id),
            Err(InstructionExecutionError::InvariantViolation(_))
        ));
    }
    #[test]
    fn current_owner_literal_comparison_is_exact_and_releases_scratch() {
        let owner = account(&keypair(0x42));
        for discriminant in [0x02f1, 0x0171, 0, 73] {
            let _discriminant =
                iroha_data_model::account::address::ChainDiscriminantGuard::enter(discriminant);
            let literal = owner
                .canonical_i105()
                .expect("fixture account has canonical I105");
            let mut current = OrderbookQueryCurrent::new(0).expect("empty current fits");
            assert!(
                owner_literal_matches_for_current(&owner, literal.as_bytes(), &mut current)
                    .expect("canonical literal compares")
            );
            assert_eq!(current.resident_bytes(), 0);
            let mut suffixed = literal.into_bytes();
            suffixed.push(b'x');
            assert!(
                !owner_literal_matches_for_current(&owner, &suffixed, &mut current)
                    .expect("noncanonical suffix compares")
            );
            assert_eq!(current.resident_bytes(), 0);
        }
    }
    #[test]
    fn bounded_channel_query_shares_one_current_allowance_with_trade_validation() {
        let settlement = keypair(0x43);
        let buyer = keypair(0x44);
        let provider = keypair(0x45);
        let treasury = keypair(0x46);
        let authority = account(&settlement);
        let buyer_id = account(&buyer);
        let provider_id = account(&provider);
        let mut state =
            state_with_settlement_accounts(&settlement, &buyer, &provider, &treasury, 0);
        let receipt = receipt(&provider, 1, 1, 8, 0, 10);
        transact(&mut state, 1, NOW, |transaction| {
            activate_policy(transaction, &authority);
            seed_settlement_channel(transaction, &buyer_id, &provider_id, &authority, &receipt);
            Ok(())
        })
        .expect("commit bounded channel-query fixture");
        let nexus = state.nexus_snapshot();
        let pipeline = state.installed_pipeline().clone();
        let mut configuration =
            crate::sumeragi::test_chain::TestChainConfig::new(state.world, NOW * 1_000);
        configuration.genesis_key = settlement.clone();
        configuration.pipeline = pipeline;
        configuration.governance = Some(state.gov);
        configuration.nexus = Some(nexus);
        let chain = crate::sumeragi::test_chain::CertifiedTestChain::start(configuration)
            .expect("authenticate the bounded query's actual durable history");
        let state = chain.state();
        let view = state.view();
        let unbounded_channel = read_channel(view.world(), receipt.channel_id)
            .expect("read valid unbounded channel")
            .expect("stored channel");
        let channel_bytes = view
            .world()
            .smart_contract_state()
            .get(&channel_key(receipt.channel_id))
            .expect("stored channel bytes");
        let (decoded_channel, channel_allocation) = decode_state_measured::<
            OrderbookSettlementChannelRecord,
        >(channel_bytes, "test channel")
        .expect("measure channel allocation");
        assert_eq!(decoded_channel, unbounded_channel);
        let trade_bytes = view
            .world()
            .smart_contract_state()
            .get(&trade_key(receipt.trade_id))
            .expect("stored trade bytes");
        let (trade_record, trade_allocation) =
            decode_state_measured::<OrderbookTradeRecord>(trade_bytes, "test trade")
                .expect("measure trade allocation");
        let (trade_payload, trade_payload_usage) =
            norito::core::with_decode_limits_measured(ORDERBOOK_PAYLOAD_DECODE_LIMITS_V1, || {
                decode_trade_event_v1_with_limits(
                    &trade_record.canonical_trade,
                    ORDERBOOK_PAYLOAD_DECODE_LIMITS_V1,
                )
            });
        trade_payload.expect("measure trade-payload allocation");
        let allocations = [
            channel_allocation,
            trade_allocation,
            trade_payload_usage.total_allocated_bytes(),
        ];
        let individual_allowance = allocations.into_iter().max().expect("three allocations");
        assert!(
            allocations.iter().sum::<usize>() > individual_allowance,
            "the combined measured current must exceed every individual source graph"
        );
        let limits =
            QueryLimits::default().with_singular_output_limits(SingularQueryOutputLimits::new(
                u64::try_from(STATE_MAX_BYTES).expect("state bound fits u64"),
                u64::try_from(individual_allowance).expect("fixture allocation fits u64"),
            ));
        let request = ValidQueryRequest::validate_for_client_parts(
            QueryRequest::Singular(FindSorafsOrderbookChannelById::new(receipt.channel_id).into()),
            &authority,
            &view,
            limits,
        )
        .expect("validate bounded channel query");
        let error = request
            .execute_ephemeral(view.query_handle(), &view, &authority)
            .expect_err("aggregate channel/trade current exceeds D");
        assert_eq!(error, QueryExecutionFail::CapacityLimit);
    }
    #[test]
    fn typed_queries_reject_not_found_and_invalid_limits() {
        let operator = keypair(0x29);
        let authority = account(&operator);
        let mut state = state_with_accounts(&[&operator]);
        let mut block = state.block(block_header());
        let mut stx = block.transaction();
        assert_eq!(
            FindSorafsOrderbookPolicy.execute(&stx),
            Err(QueryExecutionFail::Find(FindError::SorafsOrderbookPolicy))
        );
        assert_eq!(
            FindSorafsOrderbookStatus.execute(&stx),
            Err(QueryExecutionFail::Find(FindError::SorafsOrderbookStatus))
        );
        assert_eq!(
            FindSorafsOrderbookOrderById::new([0xE1; 32]).execute(&stx),
            Err(QueryExecutionFail::Find(FindError::SorafsOrderbookOrder(
                [0xE1; 32]
            )))
        );
        assert_eq!(
            FindSorafsOrderbookCancellationByOrderId::new([0xE2; 32]).execute(&stx),
            Err(QueryExecutionFail::Find(
                FindError::SorafsOrderbookCancellation([0xE2; 32])
            ))
        );
        assert_eq!(
            FindSorafsOrderbookReceiptById::new([0xE3; 32]).execute(&stx),
            Err(QueryExecutionFail::Find(FindError::SorafsOrderbookReceipt(
                [0xE3; 32]
            )))
        );
        activate_policy(&mut stx, &authority);
        stx.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit configured orderbook");
        state.push_block_hash_for_testing(iroha_crypto::HashOf::new(&block_header()));
        let view = state.view();
        for limit in [0, ORDERBOOK_QUERY_MAX_ITEMS_V1 + 1] {
            assert!(
                FindSorafsOrderbookOrders::new(None, None, None, limit)
                    .execute(&view)
                    .is_err()
            );
            assert!(
                FindSorafsOrderbookReceipts::new(None, None, None, limit)
                    .execute(&view)
                    .is_err()
            );
            assert!(
                FindSorafsOrderbookTrades::new(None, None, limit)
                    .execute(&view)
                    .is_err()
            );
            assert!(
                FindSorafsOrderbookChannels::new(None, None, None, limit)
                    .execute(&view)
                    .is_err()
            );
            assert!(
                FindSorafsOrderbookEvents::new(None, None, limit)
                    .execute(&view)
                    .is_err()
            );
        }
        assert!(
            FindSorafsOrderbookOrders::new(None, None, None, 1)
                .execute(&view)
                .expect("empty configured orderbook query")
                .orders
                .is_empty()
        );
        let event_page = FindSorafsOrderbookEvents::new(None, None, 1)
            .execute(&view)
            .expect("query initial committed orderbook event");
        assert_eq!(event_page.events.len(), 1);
        assert_eq!(
            event_page.events[0].event.kind,
            SorafsOrderbookLedgerEventKind::PolicyActivated
        );
    }
    #[test]
    fn query_scan_budget_is_inclusive_and_fails_closed() {
        let limits = OrderbookQueryScanLimitsV1 {
            max_inspected_records: 2,
            max_read_bytes: 3,
        };
        let mut budget = OrderbookQueryScanBudgetV1::new(limits);
        budget
            .inspect(1, "fixture page")
            .expect("first inspected record is within both bounds");
        budget
            .inspect(2, "fixture page")
            .expect("exact record and byte bounds are inclusive");
        assert_eq!(
            budget.inspect(0, "fixture page"),
            Err(QueryExecutionFail::Conversion(
                "SoraFS orderbook fixture page query exceeded inspected-record budget 2".to_owned()
            ))
        );
        let mut byte_budget = OrderbookQueryScanBudgetV1::new(limits);
        assert_eq!(
            byte_budget.inspect(4, "fixture page"),
            Err(QueryExecutionFail::Conversion(
                "SoraFS orderbook fixture page query exceeded encoded-read-byte budget 3"
                    .to_owned()
            ))
        );
    }
}
