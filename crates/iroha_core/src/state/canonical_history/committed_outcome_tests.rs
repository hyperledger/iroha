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
fn bounded_outcome_matches_the_full_carrier_for_applied_rejected_and_absent_inputs() {
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
    assert!(
        bounded(state, height, &absent, &budget)
            .unwrap()
            .matched_results()
            .is_empty()
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
