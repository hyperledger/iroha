//! The bounded committed-outcome reader agrees with the full carrier, reads no transaction
//! body, keeps its bounds exact and refuses substituted frames.

use super::*;
use crate::{
    state::{State, World},
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};
use iroha_allocation::{AllocationBudget, AllocationRefusal};
use iroha_data_model::{
    Level,
    isi::{InstructionBox, Log, Unregister},
    transaction::{
        SignedTransaction,
        signed::{
            SealedTransactionCommitmentPayload, SealedTransactionReveal,
            SignedSealedTransactionCommitment, compute_sealed_transaction_commitment,
        },
    },
};
use norito::{DecodeLimits, core::DecodeBudgetContext};

const WORK: u64 = 500;
const BYTES: u64 = 1 << 30;

fn read_budget(frames: usize, decoded: usize) -> CanonicalHistoryReadBudget {
    CanonicalHistoryReadBudget::new(
        AllocationBudget::new(frames),
        DecodeBudgetContext::new(DecodeLimits::new(
            decoded,
            decoded,
            decoded,
            decoded,
            norito::core::MAX_VALUE_NESTING_DEPTH,
        )),
    )
}

fn generous() -> CanonicalHistoryReadBudget {
    read_budget(256 << 20, usize::MAX)
}

/// One applied `Log` of `log_bytes` and one rejected input committed together at height 2.
fn outcome_chain(log_bytes: usize) -> (CertifiedTestChain, Vec<SignedTransaction>) {
    let config = TestChainConfig::new(World::new(), 0);
    let signer = config.genesis_key.clone();
    let mut chain = CertifiedTestChain::start(config).unwrap();
    let applied = chain.sign(
        &signer,
        [InstructionBox::from(Log::new(
            Level::INFO,
            "x".repeat(log_bytes),
        ))],
        1001,
    );
    let rejected = chain.sign(
        &signer,
        [InstructionBox::from(Unregister::domain(
            iroha_model_base::domain::DomainId::try_new("missing_outcome_domain", "universal")
                .unwrap(),
        ))],
        1002,
    );
    assert_eq!(
        chain.commit(vec![applied.clone(), rejected.clone()]),
        vec![true, false]
    );
    (chain, vec![applied, rejected])
}

/// The matched results of the complete checkpoint carrier, as the outcome kernel reads them.
fn full_results(
    state: &State,
    height: NonZeroUsize,
    identity: &HashOf<TransactionEntrypoint>,
) -> Vec<Result<(), TransactionRejectionReason>> {
    let budget = generous();
    let carrier = state
        .read_executed_carrier_from_checkpoints(height, WORK, BYTES, &budget)
        .unwrap();
    let mut results = Vec::new();
    carrier
        .visit_network_transactions(carrier.block().hash(), |entrypoint, result| {
            let alias = matches!(
                entrypoint,
                TransactionEntrypoint::SealedReveal(reveal)
                    if &reveal.signed_transaction().hash_as_entrypoint() == identity
            );
            if &entrypoint.hash() == identity || alias {
                results.push(result.0.as_ref().map(drop).map_err(Clone::clone));
            }
        })
        .unwrap();
    results
}

fn bounded(
    state: &State,
    height: NonZeroUsize,
    identity: &HashOf<TransactionEntrypoint>,
    budget: &CanonicalHistoryReadBudget,
) -> Result<CommittedNetworkOutcome, ReadError> {
    state.read_committed_network_outcome(height, identity, WORK, BYTES, budget)
}

fn conversion(error: ReadError) -> String {
    match error {
        ExecutionAttemptError::Rejected(QueryExecutionFail::Conversion(message)) => message,
        other => panic!("expected a completed conversion rejection: {other:?}"),
    }
}

#[test]
fn compact_length_decoder_matches_the_norito_writer_and_refuses_noncanonical_forms() {
    for value in [
        0_u64,
        1,
        127,
        128,
        255,
        16_383,
        16_384,
        (1 << 21) - 1,
        1 << 21,
        u64::from(u32::MAX),
        u64::MAX - 1,
        u64::MAX,
    ] {
        let mut encoded = Vec::new();
        norito::core::write_varint_len_to_vec(&mut encoded, value);
        let used = encoded.len();
        assert!(used <= longest_compact_len_prefix());
        // Bytes after the prefix belong to the next field and are not consumed.
        encoded.extend_from_slice(&[0xAA, 0x01]);
        assert_eq!(decode_compact_len(&encoded), Some((value, used)), "{value}");
    }
    let overflow = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02];
    for refused in [
        &[][..],
        &[0x80],
        &[0x80, 0x00],
        &[0x81, 0x80, 0x00],
        &[0xFF; 10],
        &overflow,
    ] {
        assert_eq!(decode_compact_len(refused), None, "{refused:?}");
    }
}

#[test]
fn bounded_outcome_matches_applied_and_rejected_inputs_and_refuses_unresolved_identity() {
    let (chain, transactions) = outcome_chain(16);
    let state = chain.state();
    let height = NonZeroUsize::new(2).unwrap();
    let header = chain.committed(2).block().header();
    let budget = read_budget(1 << 20, 16 << 20);
    for (transaction, applied) in transactions.iter().zip([true, false]) {
        let identity = transaction.hash_as_entrypoint();
        let outcome = bounded(state, height, &identity, &budget).unwrap();
        assert_eq!(outcome.header(), &header);
        assert_eq!(
            outcome.matched_results(),
            full_results(state, height, &identity).as_slice()
        );
        let [result] = outcome.matched_results() else {
            panic!("one exact Network input")
        };
        assert_eq!(result.is_ok(), applied);
    }
    let absent = HashOf::from_untyped_unchecked(Hash::new(b"absent bounded outcome identity"));
    assert_eq!(
        conversion(bounded(state, height, &absent, &budget).unwrap_err()),
        "committed Network identity has no authenticated outcome"
    );
    assert_eq!(
        budget.frames().reserved_bytes(),
        0,
        "no window outlives the read"
    );
}

#[test]
fn bounded_outcome_reads_a_transaction_larger_than_its_frame_pool_without_its_body() {
    let log_bytes = 3 << 20;
    let (chain, transactions) = outcome_chain(log_bytes);
    let state = chain.state();
    let height = NonZeroUsize::new(2).unwrap();
    let wire_len = chain
        .kura()
        .canonical_block_wire_bytes_for_testing(height)
        .unwrap()
        .len();
    assert!(wire_len > log_bytes);
    let pool = 256 << 10;
    let budget = read_budget(pool, 4 << 20);
    let expected: Vec<_> = transactions
        .iter()
        .map(|transaction| full_results(state, height, &transaction.hash_as_entrypoint()))
        .collect();
    chain.kura().reset_canonical_query_reads_for_test();
    for (transaction, expected) in transactions.iter().zip(expected) {
        let outcome = bounded(state, height, &transaction.hash_as_entrypoint(), &budget).unwrap();
        assert_eq!(outcome.matched_results(), expected.as_slice());
    }
    let (windows, bytes) = chain.kura().canonical_query_reads_for_test();
    assert!(
        bytes < u64::try_from(pool).unwrap(),
        "two bounded reads loaded {bytes} bytes in {windows} windows of a {wire_len}-byte frame"
    );
    // The whole-carrier reader cannot hold this frame in the same read budget: the frame
    // alone exceeds the pool, which is a demand that can never fit rather than a busy pool.
    let refused = state.read_executed_carrier_from_checkpoints(height, WORK, BYTES, &budget);
    let Err(ExecutionAttemptError::Deferred(deferred)) = refused else {
        panic!("the full carrier must be refused locally: {refused:?}");
    };
    assert!(
        matches!(
            deferred.allocation_refusal(),
            Some(AllocationRefusal::ExceedsLimit { requested_bytes, limit_bytes })
                if *requested_bytes == wire_len && *limit_bytes == pool
        ),
        "{deferred:?}"
    );
}

#[test]
fn bounded_outcome_walks_successor_certificates_and_records_their_identities() {
    let (mut chain, transactions) = outcome_chain(16);
    for _ in 0..3 {
        chain.commit(Vec::new());
    }
    assert_eq!(chain.height(), 5);
    let state = chain.state();
    let height = NonZeroUsize::new(2).unwrap();
    let budget = generous();
    for transaction in &transactions {
        let identity = transaction.hash_as_entrypoint();
        let outcome = bounded(state, height, &identity, &budget).unwrap();
        assert_eq!(
            outcome.matched_results(),
            full_results(state, height, &identity).as_slice()
        );
    }
    let recorded: Vec<u64> = chain
        .kura()
        .history_checkpoints()
        .candidates(2, 5)
        .into_iter()
        .map(|(height, _)| height)
        .collect();
    assert!(recorded.contains(&2), "{recorded:?}");
}

#[test]
fn bounded_outcome_cumulative_decoder_refusal_can_succeed_on_identical_retry() {
    let (mut chain, transactions) = outcome_chain(16);
    for _ in 0..6 {
        chain.commit(Vec::new());
    }
    let state = chain.state();
    let height = NonZeroUsize::new(2).unwrap();
    let identity = transactions[0].hash_as_entrypoint();
    // Measure the exact target and one authenticated successor. This budget can
    // advance each retry by at least one height without funding the entire cold walk.
    chain.kura().history_checkpoints().clear();
    // The full carrier can authenticate this empty successor without asserting an outcome
    // for our target identity. Its checkpoint seeds the measured two-frame descent.
    state
        .read_executed_carrier_from_checkpoints(
            NonZeroUsize::new(3).unwrap(),
            WORK,
            BYTES,
            &generous(),
        )
        .unwrap();
    let measured = DecodeBudgetContext::new(DecodeLimits::new(
        usize::MAX,
        usize::MAX,
        usize::MAX,
        usize::MAX,
        norito::core::MAX_VALUE_NESTING_DEPTH,
    ));
    let measuring_budget =
        CanonicalHistoryReadBudget::new(AllocationBudget::new(1 << 20), measured.clone());
    let expected = bounded(state, height, &identity, &measuring_budget).unwrap();
    let limit = usize::try_from(measured.consumed_allocated_bytes()).unwrap();
    assert!(limit > 0);

    chain.kura().history_checkpoints().clear();
    let mut refusals = 0;
    // Every attempt is the same query with the same limits and a fresh request owner.
    // A refused descent retains the identities it did authenticate, so later attempts
    // can start closer to the target without changing the request or its budget.
    for _ in 0..=chain.height() {
        let context = DecodeBudgetContext::new(DecodeLimits::new(
            usize::MAX,
            usize::MAX,
            usize::MAX,
            limit,
            norito::core::MAX_VALUE_NESTING_DEPTH,
        ));
        let budget = CanonicalHistoryReadBudget::new(AllocationBudget::new(1 << 20), context);
        match bounded(state, height, &identity, &budget) {
            Ok(outcome) => {
                assert!(
                    refusals > 0,
                    "a cold descent must exceed the short-walk budget"
                );
                assert_eq!(outcome.matched_results(), expected.matched_results());
                return;
            }
            Err(ExecutionAttemptError::Deferred(deferred)) => {
                assert!(
                    matches!(
                        deferred
                            .decode_refusal()
                            .map(norito::core::DecodeLocalRefusal::resource_error),
                        Some(norito::core::DecodeResourceError::TotalAllocationExceeded { .. })
                    ),
                    "{deferred:?}"
                );
                refusals += 1;
            }
            Err(other) => panic!("unexpected completed refusal: {other:?}"),
        }
    }
    panic!("identical retries failed to finish the checkpoint descent");
}

/// A sealed commitment at height 2 and its applied reveal at height 3. Returns the chain, the
/// revealed signed transaction and the reveal's outer identity.
fn sealed_reveal_chain() -> (
    CertifiedTestChain,
    SignedTransaction,
    HashOf<TransactionEntrypoint>,
) {
    let config = TestChainConfig::new(World::new(), 1_000);
    let genesis = config.genesis_key.clone();
    let mut chain = CertifiedTestChain::start(config).unwrap();
    let signed = chain.sign(
        &genesis,
        [InstructionBox::from(Log::new(
            Level::INFO,
            "bounded sealed outcome".into(),
        ))],
        1_001,
    );
    let salt = [0xA7; 32];
    let commitment = compute_sealed_transaction_commitment(&chain.network_id(), &signed, salt, 4);
    let sealed = SignedSealedTransactionCommitment::sign(
        SealedTransactionCommitmentPayload::new(
            chain.network_id(),
            signed.authority().clone(),
            commitment,
            3,
            4,
            None,
        ),
        genesis.private_key(),
    );
    chain.commit_entrypoints(vec![TransactionEntrypoint::SealedCommitment(sealed)]);
    let reveal = TransactionEntrypoint::SealedReveal(SealedTransactionReveal::new(
        commitment,
        signed.clone(),
        salt,
    ));
    let reveal_hash = reveal.hash();
    let committed = chain.commit_entrypoints(vec![reveal]);
    assert!(
        committed
            .block()
            .network_output_at(0)
            .unwrap()
            .1
            .result
            .0
            .is_ok()
    );
    (chain, signed, reveal_hash)
}

#[test]
fn bounded_outcome_resolves_a_sealed_reveal_by_outer_identity_and_signed_alias() {
    let (chain, signed, reveal_hash) = sealed_reveal_chain();
    let alias = signed.hash_as_entrypoint();
    assert_ne!(alias, reveal_hash);
    let state = chain.state();
    let height = NonZeroUsize::new(3).unwrap();
    for identity in [reveal_hash, alias] {
        let outcome = bounded(state, height, &identity, &generous()).unwrap();
        assert_eq!(
            outcome.matched_results(),
            full_results(state, height, &identity).as_slice()
        );
        assert!(matches!(outcome.matched_results(), [Ok(())]));
    }
}

#[test]
fn bounded_outcome_refuses_a_substituted_sealed_reveal_instead_of_resolving_its_alias() {
    let (chain, signed, reveal_hash) = sealed_reveal_chain();
    let alias = signed.hash_as_entrypoint();
    let state = chain.state();
    let height = NonZeroUsize::new(3).unwrap();
    let wire = chain
        .kura()
        .canonical_block_wire_bytes_for_testing(height)
        .unwrap();
    // Flip one byte of the revealed payload: its alias would change, and nothing but the
    // whole reveal's committed input hash can tell.
    let payload = norito::codec::encode_adaptive(signed.payload());
    let position = wire
        .windows(payload.len())
        .position(|window| window == payload.as_slice())
        .expect("the revealed payload appears verbatim in the frame");
    let flipped = position + payload.len() / 2;
    chain.kura().overwrite_native_frame_bytes_for_test(
        height,
        u64::try_from(flipped).unwrap(),
        &[wire[flipped] ^ 1],
    );
    for identity in [reveal_hash, alias] {
        let error = bounded(state, height, &identity, &generous()).unwrap_err();
        assert_eq!(
            conversion(error),
            "sealed reveal differs from its committed Network input hash"
        );
    }
}

#[test]
fn bounded_outcome_reads_an_evicted_target_frame() {
    let (chain, transactions) = outcome_chain(16);
    let state = chain.state();
    let height = NonZeroUsize::new(2).unwrap();
    let expected: Vec<_> = transactions
        .iter()
        .map(|transaction| full_results(state, height, &transaction.hash_as_entrypoint()))
        .collect();
    chain.kura().evict_native_frame_for_test(height);
    for (transaction, expected) in transactions.iter().zip(expected) {
        let outcome = bounded(
            state,
            height,
            &transaction.hash_as_entrypoint(),
            &generous(),
        )
        .unwrap();
        assert_eq!(outcome.matched_results(), expected.as_slice());
    }
}

#[test]
fn bounded_outcome_refuses_a_substituted_unmatched_output_instead_of_answering() {
    let (chain, transactions) = outcome_chain(16);
    let state = chain.state();
    let height = NonZeroUsize::new(2).unwrap();
    let wire = chain
        .kura()
        .canonical_block_wire_bytes_for_testing(height)
        .unwrap();
    // The rejected input's output is hashed but never decoded when the applied one is read.
    let rejected = chain.committed(2).block().execution_outputs()[1].clone();
    let encoded = norito::codec::encode_adaptive(&rejected);
    let position = wire
        .windows(encoded.len())
        .position(|window| window == encoded.as_slice())
        .expect("the canonical output bytes appear verbatim in the frame");
    let last = position + encoded.len() - 1;
    chain.kura().overwrite_native_frame_bytes_for_test(
        height,
        u64::try_from(last).unwrap(),
        &[wire[last] ^ 1],
    );
    let error = bounded(
        state,
        height,
        &transactions[0].hash_as_entrypoint(),
        &generous(),
    )
    .unwrap_err();
    assert_eq!(
        conversion(error),
        "execution outputs differ from the certified output commitment"
    );
}

#[test]
fn bounded_outcome_work_and_byte_bounds_are_exact() {
    let (chain, transactions) = outcome_chain(16);
    let state = chain.state();
    let height = NonZeroUsize::new(2).unwrap();
    let identity = transactions[0].hash_as_entrypoint();
    let budget = generous();
    chain.kura().reset_canonical_query_reads_for_test();
    bounded(state, height, &identity, &budget).unwrap();
    let (_, read) = chain.kura().canonical_query_reads_for_test();
    // One walked frame plus max(two inputs, two outputs) rows is the complete work.
    let work = 3;
    let read_with = |max_work, max_bytes| {
        state.read_committed_network_outcome(height, &identity, max_work, max_bytes, &budget)
    };
    read_with(work, read).unwrap();
    for (max_work, max_bytes) in [(work - 1, read), (work, read - 1)] {
        assert!(matches!(
            read_with(max_work, max_bytes),
            Err(ExecutionAttemptError::Rejected(
                QueryExecutionFail::GasBudgetExceeded
            ))
        ));
    }
    assert!(matches!(
        read_with(0, read),
        Err(ExecutionAttemptError::Rejected(
            QueryExecutionFail::GasBudgetExceeded
        ))
    ));
}

#[test]
fn bounded_outcome_refuses_genesis_and_a_contradicted_journal() {
    let (chain, transactions) = outcome_chain(16);
    let state = chain.state();
    let identity = transactions[0].hash_as_entrypoint();
    let genesis = bounded(state, NonZeroUsize::MIN, &identity, &generous()).unwrap_err();
    assert!(conversion(genesis).contains("height-two successor"));
    let mut journal = state.block_hashes.block_and_revert();
    journal.push_for_tests(HashOf::from_untyped_unchecked(Hash::new(
        b"contradicted bounded outcome journal",
    )));
    journal.commit_for_tests();
    let contradicted =
        bounded(state, NonZeroUsize::new(2).unwrap(), &identity, &generous()).unwrap_err();
    assert_eq!(
        conversion(contradicted),
        "native execution parent contradicts State hash at 2"
    );
}

#[test]
fn bounded_outcome_refuses_a_substituted_reveal_variant_instead_of_alias_absence() {
    let (chain, signed, outer_identity) = sealed_reveal_chain();
    let height = NonZeroUsize::new(3).unwrap();
    let wire = chain
        .kura()
        .canonical_block_wire_bytes_for_testing(height)
        .unwrap();
    let reveal =
        norito::codec::encode_adaptive(&chain.committed(3).block().external_entrypoints_slice()[0]);
    let position = wire
        .windows(reveal.len())
        .position(|window| window == reveal.as_slice())
        .expect("the reveal appears verbatim in its original frame");
    assert_eq!(
        &wire[position..position + size_of::<u32>()],
        &EntrypointTag::SealedReveal.wire()
    );
    // No accepted non-reveal tag may turn an unresolved committed alias into
    // an authenticated empty result. Positive outer-identity outcomes remain unchanged.
    for tag in [
        EntrypointTag::External,
        EntrypointTag::SealedCommitment,
        EntrypointTag::AnonymousBallot,
    ] {
        chain.kura().overwrite_native_frame_bytes_for_test(
            height,
            u64::try_from(position).unwrap(),
            &tag.wire(),
        );
        let error = bounded(
            chain.state(),
            height,
            &signed.hash_as_entrypoint(),
            &generous(),
        )
        .unwrap_err();
        assert_eq!(
            conversion(error),
            "committed Network identity has no authenticated outcome"
        );
        let outer = bounded(chain.state(), height, &outer_identity, &generous()).unwrap();
        assert!(matches!(outer.matched_results(), [Ok(())]));
    }
}

#[test]
fn bounded_outcome_scans_known_and_retired_tags_even_for_other_network_inputs() {
    let (chain, transactions) = outcome_chain(16);
    let height = NonZeroUsize::new(2).unwrap();
    let expected = transactions
        .iter()
        .map(|transaction| full_results(chain.state(), height, &transaction.hash_as_entrypoint()))
        .collect::<Vec<_>>();
    let wire = chain
        .kura()
        .canonical_block_wire_bytes_for_testing(height)
        .unwrap();
    let entrypoint =
        norito::codec::encode_adaptive(&chain.committed(2).block().external_entrypoints_slice()[1]);
    let position = wire
        .windows(entrypoint.len())
        .position(|window| window == entrypoint.as_slice())
        .expect("the second input appears verbatim in its original frame");

    // Pin the parser's known tag to a canonical structural carrier. This does not
    // admit or execute a ballot, or assert proof validity: only its tag is copied
    // into an ordinary input whose original hash and result remain authenticated.
    let anonymous =
        norito::codec::encode_adaptive(&crate::tx::anonymous_ballot_tests::entrypoint());
    let tag = &anonymous[..size_of::<u32>()];
    assert_eq!(tag, EntrypointTag::AnonymousBallot.wire());
    chain.kura().overwrite_native_frame_bytes_for_test(
        height,
        u64::try_from(position).unwrap(),
        tag,
    );
    for (transaction, expected) in transactions.iter().zip(&expected) {
        let outcome = bounded(
            chain.state(),
            height,
            &transaction.hash_as_entrypoint(),
            &generous(),
        )
        .unwrap();
        assert_eq!(outcome.matched_results(), expected.as_slice());
    }

    // Every input is still scanned even when the first ordinary identity already
    // matches. Retired tag 3 and unknown tags remain invalid for both identities.
    for tag in [3_u32, 5, u32::MAX] {
        chain.kura().overwrite_native_frame_bytes_for_test(
            height,
            u64::try_from(position).unwrap(),
            &tag.to_le_bytes(),
        );
        for transaction in &transactions {
            let error = bounded(
                chain.state(),
                height,
                &transaction.hash_as_entrypoint(),
                &generous(),
            )
            .unwrap_err();
            assert_eq!(conversion(error), "Network input has an unknown variant");
        }
    }
}

#[test]
fn bounded_outcome_checks_input_work_before_inspecting_entrypoint_bodies() {
    let (chain, transactions) = outcome_chain(16);
    let height = NonZeroUsize::new(2).unwrap();
    let wire = chain
        .kura()
        .canonical_block_wire_bytes_for_testing(height)
        .unwrap();
    let entrypoint =
        norito::codec::encode_adaptive(&chain.committed(2).block().external_entrypoints_slice()[0]);
    let position = wire
        .windows(entrypoint.len())
        .position(|window| window == entrypoint.as_slice())
        .expect("the entrypoint appears verbatim in its original frame");
    chain.kura().overwrite_native_frame_bytes_for_test(
        height,
        u64::try_from(position).unwrap(),
        &u32::MAX.to_le_bytes(),
    );
    // One frame plus two input rows needs three work units. Refuse either smaller
    // allowance before inspecting the malformed entrypoint's tag or payload.
    for max_work in [1, 2] {
        let result = chain.state().read_committed_network_outcome(
            height,
            &transactions[0].hash_as_entrypoint(),
            max_work,
            BYTES,
            &generous(),
        );
        assert!(
            matches!(
                result,
                Err(ExecutionAttemptError::Rejected(
                    QueryExecutionFail::GasBudgetExceeded
                ))
            ),
            "over-budget input rows must not be inspected: {result:?}"
        );
    }
    // At the exact allowance the reader reaches the malformed tag. This prevents
    // a permanently rejecting implementation from satisfying the refusal control.
    let exact = chain
        .state()
        .read_committed_network_outcome(
            height,
            &transactions[0].hash_as_entrypoint(),
            3,
            BYTES,
            &generous(),
        )
        .unwrap_err();
    assert_eq!(conversion(exact), "Network input has an unknown variant");
}

#[test]
fn bounded_outcome_per_item_refusal_identifies_target_and_skippable_ancestry() {
    use crate::execution_attempt::ExecutionPhase;

    let (mut chain, transactions) = outcome_chain(16);
    chain.commit(Vec::new());
    let certificate_bytes =
        norito::codec::encode_adaptive(chain.committed(3).block().commit_certificate().unwrap())
            .len();
    let frames = certificate_bytes - 1;
    let target_identity = chain.committed(3).block().external_entrypoints_slice()[0].hash();
    for (height, identity, expected_phase) in [
        (
            2,
            transactions[0].hash_as_entrypoint(),
            ExecutionPhase::HistoryAncestry,
        ),
        (3, target_identity, ExecutionPhase::HistoryTarget),
    ] {
        chain.kura().clear_history_checkpoints_for_testing();
        let refused = bounded(
            chain.state(),
            NonZeroUsize::new(height).unwrap(),
            &identity,
            &read_budget(frames, usize::MAX),
        )
        .unwrap_err();
        let ExecutionAttemptError::Deferred(original) = refused else {
            panic!("the original certificate window must be refused locally");
        };
        assert_eq!(original.phase(), Some(expected_phase));
        assert!(matches!(
            original.allocation_refusal(),
            Some(AllocationRefusal::ExceedsLimit {
                requested_bytes,
                limit_bytes,
            }) if *requested_bytes == certificate_bytes && *limit_bytes == frames
        ));
    }
    // A verified checkpoint still requires the target's own certificate on every read.
    assert!(
        !full_results(
            chain.state(),
            NonZeroUsize::new(3).unwrap(),
            &target_identity,
        )
        .is_empty()
    );
    let refused = bounded(
        chain.state(),
        NonZeroUsize::new(3).unwrap(),
        &target_identity,
        &read_budget(frames, usize::MAX),
    )
    .unwrap_err();
    assert!(matches!(
        refused,
        ExecutionAttemptError::Deferred(original)
            if original.phase() == Some(ExecutionPhase::HistoryTarget)
                && matches!(original.allocation_refusal(),
                    Some(AllocationRefusal::ExceedsLimit { .. }))
    ));
}

#[test]
fn bounded_outcome_refuses_a_substituted_input_identity_before_returning_its_result() {
    let (chain, transactions) = outcome_chain(16);
    let height = NonZeroUsize::new(2).unwrap();
    let original_identity = transactions[0].hash_as_entrypoint();
    let original = bounded(chain.state(), height, &original_identity, &generous()).unwrap();
    assert!(matches!(original.matched_results(), [Ok(())]));
    let wire = chain
        .kura()
        .canonical_block_wire_bytes_for_testing(height)
        .unwrap();
    let committed = chain.committed(2);
    let context = &committed.block().execution_context().unwrap().external[0];
    let encoded = norito::codec::encode_adaptive(context);
    let positions: Vec<_> = wire
        .windows(encoded.len())
        .enumerate()
        .filter_map(|(index, bytes)| (bytes == encoded.as_slice()).then_some(index))
        .collect();
    assert_eq!(
        positions.len(),
        1,
        "the original input context must occur exactly once"
    );
    let fabricated = HashOf::<TransactionEntrypoint>::from_untyped_unchecked(Hash::new(
        b"adversarial substituted committed input identity",
    ));
    assert_ne!(fabricated, original_identity);
    let mut replacement = context.clone();
    replacement.entrypoint_hash = fabricated;
    let replacement = norito::codec::encode_adaptive(&replacement);
    assert_eq!(replacement.len(), encoded.len());
    // Corrupt only the stored input-context row. The original durable header and
    // native commit certificate remain unchanged; no new finality is fabricated.
    chain.kura().overwrite_native_frame_bytes_for_test(
        height,
        u64::try_from(positions[0]).unwrap(),
        &replacement,
    );
    let error = bounded(chain.state(), height, &fabricated, &generous())
        .expect_err("substituted Network identity must not inherit the original committed output");
    let message = conversion(error);
    assert!(
        message == "execution context differs from the Network inputs committed by the header"
            || message == "certified input commitment differs from the committed Network inputs",
        "either authenticated input-root anchor must reject the substitution: {message}",
    );
}
