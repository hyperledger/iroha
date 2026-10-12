//! Binding tests of the frozen shared backend transcript.
//!
//! Every test drives the real transcript with real SHAKE256 tapes. They show
//! that each element the frozen profile says is bound changes what follows
//! when it is changed, reordered or omitted, and nothing that precedes it.
//! The known answers come from `scripts/zk_semantic_profile_reference.py`,
//! which shares no code with this crate.
//!
//! These tests establish that the implementation conforms to the frozen
//! binding. They establish no soundness level.

use fastpq_isi::{
    keccak256::Sha3_256V1,
    semantic_profile::{SemanticProfileOwnedValueV1 as Owned, SemanticProfileV1},
};

use super::{
    super::{
        frozen_record::{as_u64, field, known_answers, list, number, numbers, text},
        transcript_profile::{self, CONSTRUCTION, FRAMING_VERSION, GRINDING_BITS},
    },
    *,
};

const RELATION: &str = "fastpq:transcript:binding-test-relation:v1";
const STATEMENT: &[u8] = b"complete public statement of the binding tests";

/// The nine commitments of one transcript, in schedule order.
#[derive(Clone)]
struct Commitments {
    /// Row, joined quotient and mask, five FRI layers and the terminal.
    roots: [Digest; 8],
    current: Vec<F>,
    next: Vec<F>,
    quotient: Vec<F>,
}

impl Commitments {
    fn seeded(seed: &str) -> Self {
        let root = |label: &str| {
            let mut hash = Sha3_256V1::new();
            hash.update(format!("{seed}:{label}").as_bytes());
            hash.finalize()
        };
        let answer = |index: usize| {
            F::new(core::array::from_fn(|lane| (4 * index + lane + 1) as u64)).unwrap()
        };
        Self {
            roots: [
                root("row-root"),
                root("quotient+mask-root"),
                root("fri-root-0"),
                root("fri-root-1"),
                root("fri-root-2"),
                root("fri-root-3"),
                root("fri-root-4"),
                root("terminal-root"),
            ],
            current: (0..COMMITTED_COLUMN_COUNT).map(answer).collect(),
            next: (COMMITTED_COLUMN_COUNT..2 * COMMITTED_COLUMN_COUNT)
                .map(answer)
                .collect(),
            quotient: (2 * COMMITTED_COLUMN_COUNT..OOD_VALUES)
                .map(answer)
                .collect(),
        }
    }

    /// The oracle and root committed after verifier message `ordinal`.
    fn root_after(&self, ordinal: u8) -> (Oracle, Digest) {
        match ordinal {
            1 => (Oracle::Row, self.roots[0]),
            2 => (Oracle::QuotientAndMask, self.roots[1]),
            4..=8 => (
                Oracle::Fri(ordinal - 4),
                self.roots[usize::from(ordinal) - 2],
            ),
            9 => (Oracle::Terminal, self.roots[7]),
            _ => unreachable!("message {ordinal} is followed by no root"),
        }
    }
}

/// Everything one complete transcript run exposes.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Run {
    /// Whole raw tapes of messages 1 through 9.
    tapes: Vec<Vec<u8>>,
    /// Decoded messages 1 through 9.
    messages: Vec<Message>,
    /// Chain commitments after messages 1 through 9.
    chains: Vec<Digest>,
    /// Message 10.
    queries: Vec<u32>,
}

fn run(context: &Context, commitments: &Commitments) -> Run {
    let mut transcript = Transcript::new(context.clone());
    let mut run = Run {
        tapes: Vec::new(),
        messages: Vec::new(),
        chains: Vec::new(),
        queries: Vec::new(),
    };
    for ordinal in 1..=10 {
        let message = transcript.challenge().unwrap();
        if ordinal == 10 {
            let Message::Queries(queries) = message else {
                panic!("the last message is the query set");
            };
            run.queries = queries;
            break;
        }
        let Phase::Pending { raw, .. } = &transcript.phase else {
            panic!("a commitment is pending after message {ordinal}");
        };
        run.tapes.push(raw.as_bytes().to_vec());
        run.messages.push(message);
        if ordinal == 3 {
            transcript
                .commit_ood(
                    &commitments.current,
                    &commitments.next,
                    &commitments.quotient,
                )
                .unwrap();
        } else {
            let (oracle, root) = commitments.root_after(ordinal);
            transcript.commit_root(oracle, root).unwrap();
        }
        run.chains.push(transcript.predecessor);
    }
    assert!(matches!(transcript.phase, Phase::Complete));
    run
}

/// The frozen context built through the test prefix hook with explicit parts.
fn context_with(version: u16, catalog: &[u8], construction: &[u8], profile: &[u8]) -> Context {
    Context::with_prefix_for_test(RELATION, STATEMENT, |context| {
        FramingContext::with_prefix_for_test(version, catalog, construction, profile, context)
    })
    .unwrap()
}

fn frozen() -> Context {
    Context::with_identity(RELATION, STATEMENT).unwrap()
}

/// What a context contributes to the first leaf, parent, chain and tape.
fn fingerprint(context: &Context) -> (Digest, Digest, Digest, Vec<u8>) {
    let zero = Digest::default();
    let row = vec![0; COMMITTED_COLUMN_COUNT * 8];
    let mut transcript = Transcript::new(context.clone());
    assert_eq!(transcript.challenge().unwrap(), Message::Dummy);
    let Phase::Pending { raw, .. } = &transcript.phase else {
        panic!("the first tape is pending");
    };
    (
        context.hash_leaf(Oracle::Row, 0, &row).unwrap(),
        context.hash_parent(Oracle::Row, 1, 0, zero, zero).unwrap(),
        context.chain(Round(1), raw.as_bytes(), zero).unwrap(),
        raw.as_bytes().to_vec(),
    )
}

fn assert_all_differ(
    baseline: &(Digest, Digest, Digest, Vec<u8>),
    changed: &(Digest, Digest, Digest, Vec<u8>),
    what: &str,
) {
    assert_ne!(baseline.0, changed.0, "{what}: row leaf is not bound");
    assert_ne!(baseline.1, changed.1, "{what}: parent is not bound");
    assert_ne!(baseline.2, changed.2, "{what}: chain is not bound");
    assert_ne!(baseline.3, changed.3, "{what}: first tape is not bound");
}

fn sha3(bytes: &[u8]) -> String {
    let mut hash = Sha3_256V1::new();
    hash.update(bytes);
    hex::encode(hash.finalize().into_bytes())
}

fn limbs(value: &norito::json::Value) -> F {
    let words: Vec<u64> = value.as_array().unwrap().iter().map(as_u64).collect();
    F::new(words.try_into().unwrap()).unwrap()
}

#[test]
fn frozen_transcript_matches_the_independent_known_answers() {
    let answers = known_answers();
    let profile = transcript_profile::profile();
    assert_eq!(text(answers, "profile"), profile.name());
    assert_eq!(text(answers, "identity"), profile.id().to_string());
    assert_eq!(
        number(answers, "profile_frame_bytes"),
        profile.as_bytes().len() as u64
    );
    let inputs = field(answers, "inputs");
    assert_eq!(text(inputs, "catalog"), fastpq_isi::FASTPQ_CATALOG_V1);
    assert_eq!(text(inputs, "layout"), LAYOUT_ID);
    let relation = text(inputs, "relation");
    let statement = hex::decode(text(inputs, "statement_hex")).unwrap();

    let encoded = Context::encode_statement_context(relation, &statement).unwrap();
    assert_eq!(number(answers, "context_bytes"), encoded.len() as u64);
    assert_eq!(text(answers, "context_sha3_256"), sha3(&encoded));

    let context = Context::with_identity(relation, &statement).unwrap();
    let commitments = Commitments::seeded(text(inputs, "commitment_seed"));
    let answers_bytes = ood_bytes(
        &commitments.current,
        &commitments.next,
        &commitments.quotient,
    )
    .unwrap();
    assert_eq!(text(answers, "ood_answers_sha3_256"), sha3(&answers_bytes));
    let observed = run(&context, &commitments);

    let rounds = list(answers, "rounds");
    assert_eq!(rounds.len(), 10);
    for (index, round) in rounds.iter().enumerate() {
        let ordinal = u8::try_from(index + 1).unwrap();
        assert_eq!(number(round, "round"), u64::from(ordinal));
        assert_eq!(
            number(round, "tape_bytes"),
            Round(ordinal).tape_bytes() as u64
        );
        if ordinal == 10 {
            continue;
        }
        assert_eq!(
            text(round, "tape_sha3_256"),
            sha3(&observed.tapes[index]),
            "tape {ordinal}"
        );
        let expected = if ordinal == 3 {
            context
                .hash_ood(
                    &commitments.current,
                    &commitments.next,
                    &commitments.quotient,
                )
                .unwrap()
        } else {
            commitments.root_after(ordinal).1
        };
        assert_eq!(
            text(round, "commitment_hex"),
            hex::encode(expected.into_bytes()),
            "commitment after message {ordinal}"
        );
        assert_eq!(
            text(round, "chain_sha3_256"),
            hex::encode(observed.chains[index].into_bytes()),
            "chain after message {ordinal}"
        );
    }

    let decoded = field(answers, "decoded");
    let Message::Fields(alphas) = &observed.messages[1] else {
        panic!("message 2 holds the constraint coefficients");
    };
    assert_eq!(alphas.len(), CONSTRAINTS);
    let alpha_bytes: Vec<u8> = alphas
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect();
    assert_eq!(text(decoded, "alphas_sha3_256"), sha3(&alpha_bytes));
    assert_eq!(limbs(field(decoded, "first_alpha")), alphas[0]);
    assert_eq!(limbs(field(decoded, "last_alpha")), alphas[CONSTRAINTS - 1]);
    assert_eq!(
        observed.messages[2],
        Message::Fields(vec![limbs(field(decoded, "ood_point"))])
    );
    assert_eq!(
        observed.messages[3],
        Message::Fields(vec![limbs(field(decoded, "lambda"))])
    );
    let betas = list(decoded, "betas");
    assert_eq!(betas.len(), 5);
    for (index, beta) in betas.iter().enumerate() {
        assert_eq!(
            observed.messages[4 + index],
            Message::Fields(vec![limbs(beta)])
        );
    }
    let queries: Vec<u32> = numbers(decoded, "queries")
        .into_iter()
        .map(|position| u32::try_from(position).unwrap())
        .collect();
    assert_eq!(queries.len(), QUERY_COUNT);
    assert_eq!(observed.queries, queries);

    let oracles = [
        Oracle::Row,
        Oracle::QuotientAndMask,
        Oracle::Fri(0),
        Oracle::Fri(1),
        Oracle::Fri(2),
        Oracle::Fri(3),
        Oracle::Fri(4),
        Oracle::Terminal,
    ];
    let zero = Digest::default();
    for ((oracle, leaf), parent) in oracles
        .into_iter()
        .zip(list(answers, "zero_leaves"))
        .zip(list(answers, "zero_parents"))
    {
        let (_, _, _, size) = oracle.shape().unwrap();
        assert_eq!(
            text(leaf, "leaf_sha3_256"),
            hex::encode(
                context
                    .hash_leaf(oracle, 0, &vec![0; size])
                    .unwrap()
                    .into_bytes()
            ),
            "{oracle:?} leaf"
        );
        assert_eq!(
            text(parent, "parent_sha3_256"),
            hex::encode(
                context
                    .hash_parent(oracle, 1, 0, zero, zero)
                    .unwrap()
                    .into_bytes()
            ),
            "{oracle:?} parent"
        );
    }
}

#[test]
fn every_descriptor_parameter_is_bound_by_every_commitment_and_challenge() {
    let profile = transcript_profile::profile();
    let catalog = fastpq_isi::FASTPQ_CATALOG_V1.as_bytes();
    let construction = CONSTRUCTION.as_bytes();
    // The hook with the frozen parts is exactly the production context.
    let rebuilt = context_with(FRAMING_VERSION, catalog, construction, profile.as_bytes());
    let baseline = fingerprint(&frozen());
    assert_eq!(fingerprint(&rebuilt), baseline);
    let commitments = Commitments::seeded("descriptor-binding");
    let baseline_run = run(&frozen(), &commitments);
    assert_eq!(run(&rebuilt, &commitments), baseline_run);

    let parameters = profile.parameters();
    let encode = |parameters: &[(String, Owned)]| {
        let borrowed: Vec<_> = parameters
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_value()))
            .collect();
        SemanticProfileV1::new(profile.kind(), profile.name(), &borrowed).unwrap()
    };
    assert_eq!(encode(&parameters).as_bytes(), profile.as_bytes());
    let check = |changed: &SemanticProfileV1, what: &str| {
        assert_ne!(changed.id(), profile.id(), "{what}: identity unchanged");
        let context = context_with(FRAMING_VERSION, catalog, construction, changed.as_bytes());
        assert_all_differ(&baseline, &fingerprint(&context), what);
        let changed_run = run(&context, &commitments);
        for round in 0..9 {
            assert_ne!(
                changed_run.tapes[round],
                baseline_run.tapes[round],
                "{what}: tape {} is unchanged",
                round + 1
            );
            assert_ne!(
                changed_run.chains[round],
                baseline_run.chains[round],
                "{what}: chain {} is unchanged",
                round + 1
            );
        }
        assert_ne!(changed_run.queries, baseline_run.queries, "{what}: queries");
    };
    for index in 0..parameters.len() {
        let key = parameters[index].0.clone();
        // Changed.
        let mut changed = parameters.clone();
        changed[index].1 = match &parameters[index].1 {
            Owned::U64(number) => Owned::U64(number ^ 1),
            Owned::Text(label) => Owned::Text(format!("{label}x")),
            Owned::Bytes(bytes) => Owned::Bytes([bytes.as_slice(), &[0]].concat()),
            Owned::U64List(values) => {
                let mut values = values.clone();
                values[0] ^= 1;
                Owned::U64List(values)
            }
        };
        check(&encode(&changed), &format!("changed `{key}`"));
        // Omitted.
        let mut omitted = parameters.clone();
        omitted.remove(index);
        check(&encode(&omitted), &format!("omitted `{key}`"));
        // Reordered with its successor.
        if index + 1 < parameters.len() {
            let mut reordered = parameters.clone();
            reordered.swap(index, index + 1);
            check(&encode(&reordered), &format!("reordered `{key}`"));
        }
    }

    // The other parts of the prefix: framing version, catalog and construction.
    for (what, context) in [
        (
            "framing version",
            context_with(
                FRAMING_VERSION + 1,
                catalog,
                construction,
                profile.as_bytes(),
            ),
        ),
        (
            "catalog",
            context_with(
                FRAMING_VERSION,
                b"another-catalog",
                construction,
                profile.as_bytes(),
            ),
        ),
        (
            "construction name",
            context_with(
                FRAMING_VERSION,
                catalog,
                b"fastpq-state-transition-stark-v1",
                profile.as_bytes(),
            ),
        ),
        (
            "construction and profile exchanged",
            context_with(FRAMING_VERSION, catalog, profile.as_bytes(), construction),
        ),
        (
            "profile replaced by its identity",
            context_with(
                FRAMING_VERSION,
                catalog,
                construction,
                profile.id().as_bytes(),
            ),
        ),
    ] {
        assert_all_differ(&baseline, &fingerprint(&context), what);
        assert_ne!(
            run(&context, &commitments).queries,
            baseline_run.queries,
            "{what}"
        );
    }
}

/// A named change of one statement-context field.
type ContextMutation = (&'static str, fn(&mut StatementContext));

#[test]
fn statement_context_fields_are_bound_before_any_commitment() {
    let descriptor = || StatementContext {
        relation: RELATION.to_owned(),
        layout: LAYOUT_ID.to_owned(),
        trace_rows: fixed_u32(TRACE_ROWS),
        lde_rows: fixed_u32(LDE_ROWS),
        columns: fixed_u32(COMMITTED_COLUMN_COUNT),
        constraints: fixed_u32(CONSTRAINTS),
        modulus: MODULUS,
        extension_nonresidue: EXTENSION_NONRESIDUE,
        lde_root: LDE_ROOT,
        coset_offset: COSET_OFFSET,
        fri_arities: FRI_ARITIES.map(fixed_u32),
        fri_lengths: FRI_LENGTHS.map(fixed_u32),
        fri_degrees: FRI_DEGREES.map(fixed_u32),
        query_count: fixed_u32(QUERY_COUNT),
        query_candidates: fixed_u32(QUERY_CANDIDATES),
        statement: STATEMENT.to_vec(),
    };
    let context = |descriptor: &StatementContext| Context {
        framing: FramingContext::new(&norito::encode_canonical(descriptor).unwrap()).unwrap(),
    };
    let baseline = fingerprint(&frozen());
    assert_eq!(fingerprint(&context(&descriptor())), baseline);
    let mutations: [ContextMutation; 18] = [
        ("relation identity", |d| d.relation.push('x')),
        ("column layout", |d| d.layout.push('x')),
        ("trace rows", |d| d.trace_rows *= 2),
        ("evaluation rows", |d| d.lde_rows *= 2),
        ("committed columns", |d| d.columns += 1),
        ("constraints", |d| d.constraints += 1),
        ("modulus", |d| d.modulus -= 1),
        ("extension nonresidue", |d| d.extension_nonresidue = 11),
        ("evaluation root", |d| d.lde_root ^= 1),
        ("coset offset", |d| d.coset_offset ^= 1),
        ("first FRI arity", |d| d.fri_arities[0] *= 2),
        ("FRI arities reordered", |d| d.fri_arities.swap(1, 2)),
        ("FRI length", |d| d.fri_lengths[5] *= 2),
        ("FRI degree bound", |d| d.fri_degrees[5] += 1),
        ("query count", |d| d.query_count += 1),
        ("query candidates", |d| d.query_candidates += 1),
        ("statement", |d| d.statement[0] ^= 1),
        ("statement length", |d| d.statement.push(0)),
    ];
    for (what, mutate) in mutations {
        let mut changed = descriptor();
        mutate(&mut changed);
        assert_all_differ(&baseline, &fingerprint(&context(&changed)), what);
    }
    // Relation identity and statement exchanged is another context too.
    let exchanged = Context::with_identity(
        core::str::from_utf8(STATEMENT).unwrap(),
        RELATION.as_bytes(),
    )
    .unwrap();
    assert_all_differ(
        &baseline,
        &fingerprint(&exchanged),
        "identity and statement exchanged",
    );
}

#[test]
fn each_commitment_changes_every_later_challenge_and_no_earlier_one() {
    let context = frozen();
    let commitments = Commitments::seeded("order-binding");
    let baseline = run(&context, &commitments);
    // Commitment `position` follows message `position + 1`.
    for position in 0..9 {
        let mut changed = commitments.clone();
        match position {
            0 | 1 => changed.roots[position] = Digest::from_bytes([0xa5; 32]),
            2 => changed.next[COMMITTED_COLUMN_COUNT - 1] = F::ONE,
            _ => changed.roots[position - 1] = Digest::from_bytes([0xa5; 32]),
        }
        let observed = run(&context, &changed);
        for round in 0..9 {
            if round <= position {
                assert_eq!(
                    observed.tapes[round],
                    baseline.tapes[round],
                    "commitment {position} changed the earlier tape {}",
                    round + 1
                );
                assert_eq!(observed.messages[round], baseline.messages[round]);
            } else {
                assert_ne!(
                    observed.tapes[round],
                    baseline.tapes[round],
                    "commitment {position} is not bound by tape {}",
                    round + 1
                );
            }
            if round < position {
                assert_eq!(observed.chains[round], baseline.chains[round]);
            } else {
                assert_ne!(observed.chains[round], baseline.chains[round]);
            }
        }
        assert_ne!(
            observed.queries, baseline.queries,
            "commitment {position} is not bound by the query positions"
        );
    }
}

#[test]
fn every_out_of_domain_answer_is_bound_before_the_batching_scalar() {
    let context = frozen();
    let commitments = Commitments::seeded("ood-binding");
    let baseline = run(&context, &commitments);
    let digest = |commitments: &Commitments| {
        context
            .hash_ood(
                &commitments.current,
                &commitments.next,
                &commitments.quotient,
            )
            .unwrap()
    };
    let expected = digest(&commitments);
    let mut seen = vec![expected];
    for index in 0..OOD_VALUES {
        for lane in 0..4 {
            let mut changed = commitments.clone();
            let target = if index < COMMITTED_COLUMN_COUNT {
                &mut changed.current[index]
            } else if index < 2 * COMMITTED_COLUMN_COUNT {
                &mut changed.next[index - COMMITTED_COLUMN_COUNT]
            } else {
                &mut changed.quotient[index - 2 * COMMITTED_COLUMN_COUNT]
            };
            let mut words = target.coefficients();
            words[lane] ^= 1 << 40;
            *target = F::new(words).unwrap();
            let observed = digest(&changed);
            assert!(
                !seen.contains(&observed),
                "answer {index} lane {lane} is not bound"
            );
            if lane == 0 {
                seen.push(observed);
            }
            // The whole transcript for the first, a middle and the last answers.
            if lane == 3 && [0, 300, 301, 601, 602, 603].contains(&index) {
                let run = run(&context, &changed);
                assert_eq!(run.tapes[..3], baseline.tapes[..3]);
                assert_ne!(
                    run.tapes[3], baseline.tapes[3],
                    "lambda tape, answer {index}"
                );
                assert_ne!(run.queries, baseline.queries);
            }
        }
    }
    // Reordered rows and halves.
    let mut swapped = commitments.clone();
    core::mem::swap(&mut swapped.current, &mut swapped.next);
    assert_ne!(digest(&swapped), expected);
    assert_ne!(run(&context, &swapped).tapes[3], baseline.tapes[3]);
    let mut halves = commitments.clone();
    halves.quotient.swap(0, 1);
    assert_ne!(digest(&halves), expected);
    let mut neighbours = commitments.clone();
    neighbours.current.swap(0, 1);
    assert_ne!(digest(&neighbours), expected);
    // An omitted or extra answer is refused and aborts the attempt.
    for (current, next, quotient) in [
        (300, 301, 2),
        (301, 300, 2),
        (301, 301, 1),
        (302, 301, 2),
        (301, 301, 3),
        (0, 0, 0),
    ] {
        let mut transcript = Transcript::new(context.clone());
        transcript.challenge().unwrap();
        transcript
            .commit_root(Oracle::Row, commitments.roots[0])
            .unwrap();
        transcript.challenge().unwrap();
        transcript
            .commit_root(Oracle::QuotientAndMask, commitments.roots[1])
            .unwrap();
        transcript.challenge().unwrap();
        assert!(
            transcript
                .commit_ood(
                    &vec![F::ONE; current],
                    &vec![F::ONE; next],
                    &vec![F::ONE; quotient]
                )
                .is_err()
        );
        assert!(matches!(transcript.phase, Phase::Aborted));
        assert!(transcript.challenge().is_err());
    }
}

#[test]
fn reordered_or_omitted_commitments_are_refused_or_change_the_queries() {
    let context = frozen();
    let commitments = Commitments::seeded("reorder-binding");
    let baseline = run(&context, &commitments);
    // Two roots exchanged: everything after the earlier one changes.
    for first in 0..8 {
        for second in first + 1..8 {
            let mut exchanged = commitments.clone();
            exchanged.roots.swap(first, second);
            let observed = run(&context, &exchanged);
            assert_ne!(
                observed.queries, baseline.queries,
                "roots {first} and {second} exchanged"
            );
            // Root `first` follows message `first + 1`, or `first + 2` after the
            // out-of-domain answers.
            let message = if first < 2 { first + 1 } else { first + 2 };
            assert_eq!(observed.tapes[..message], baseline.tapes[..message]);
            assert_ne!(observed.tapes[message], baseline.tapes[message]);
        }
    }
    // A commitment under another oracle than the scheduled one is refused.
    let oracles = [
        Oracle::Row,
        Oracle::QuotientAndMask,
        Oracle::Fri(0),
        Oracle::Fri(1),
        Oracle::Fri(2),
        Oracle::Fri(3),
        Oracle::Fri(4),
        Oracle::Terminal,
    ];
    for ordinal in 1..=9_u8 {
        for oracle in oracles {
            if ordinal != 3 && oracle == commitments.root_after(ordinal).0 {
                continue;
            }
            let mut transcript = advance(&context, &commitments, ordinal);
            assert!(matches!(
                transcript.commit_root(oracle, Digest::default()),
                Err(BindingError::Phase)
            ));
            assert!(matches!(transcript.phase, Phase::Aborted));
            assert!(transcript.challenge().is_err());
        }
        // Out-of-domain answers offered in place of a root.
        if ordinal != 3 {
            let mut transcript = advance(&context, &commitments, ordinal);
            assert!(
                transcript
                    .commit_ood(
                        &commitments.current,
                        &commitments.next,
                        &commitments.quotient
                    )
                    .is_err()
            );
            assert!(matches!(transcript.phase, Phase::Aborted));
        }
        // An omitted commitment: the next message cannot be derived.
        let mut transcript = advance(&context, &commitments, ordinal);
        assert!(matches!(transcript.challenge(), Err(BindingError::Phase)));
        assert!(matches!(transcript.phase, Phase::Aborted));
        // A commitment repeated before the next message is refused as well.
        let mut transcript = advance(&context, &commitments, ordinal);
        commit_scheduled(&mut transcript, &commitments, ordinal);
        assert!(
            transcript
                .commit_root(Oracle::Row, Digest::default())
                .is_err()
        );
    }
    // Zero grinding: nine commitments and ten messages, with no nonce step.
    assert_eq!(GRINDING_BITS, 0);
    let grinding: Vec<_> = transcript_profile::profile()
        .parameters()
        .into_iter()
        .filter(|(key, _)| key.starts_with("grinding"))
        .collect();
    assert_eq!(
        grinding,
        [
            ("grinding_bits".to_owned(), Owned::U64(0)),
            ("grinding_nonce".to_owned(), Owned::Text("none".to_owned())),
        ]
    );
    assert_eq!(baseline.chains.len(), 9);
    assert_eq!(baseline.queries.len(), QUERY_COUNT);
    let mut complete = advance(&context, &commitments, 9);
    commit_scheduled(&mut complete, &commitments, 9);
    assert!(matches!(complete.challenge(), Ok(Message::Queries(_))));
    assert!(matches!(complete.phase, Phase::Complete));
    assert!(complete.challenge().is_err());
    assert!(
        complete
            .commit_root(Oracle::Terminal, Digest::default())
            .is_err()
    );
}

/// A transcript that has derived message `ordinal` and awaits its commitment.
fn advance(context: &Context, commitments: &Commitments, ordinal: u8) -> Transcript {
    let mut transcript = Transcript::new(context.clone());
    for earlier in 1..ordinal {
        transcript.challenge().unwrap();
        commit_scheduled(&mut transcript, commitments, earlier);
    }
    transcript.challenge().unwrap();
    transcript
}

fn commit_scheduled(transcript: &mut Transcript, commitments: &Commitments, ordinal: u8) {
    if ordinal == 3 {
        transcript
            .commit_ood(
                &commitments.current,
                &commitments.next,
                &commitments.quotient,
            )
            .unwrap();
    } else {
        let (oracle, root) = commitments.root_after(ordinal);
        transcript.commit_root(oracle, root).unwrap();
    }
}

/// Exploratory cost of one complete transcript replay: ten atomic tapes, the
/// out-of-domain commitment and nine chain commitments for a fixed statement.
///
/// The figure is a single-machine exploratory observation bound to the frozen
/// profile identity it prints. It is not a final measurement, a consensus
/// bound or a qualification result; H.3 measures with the measurement harness.
#[test]
#[ignore = "exploratory timing of the frozen transcript; run with --release --nocapture"]
fn exploratory_cost_of_one_complete_transcript() {
    let context = frozen();
    let commitments = Commitments::seeded("exploratory-cost");
    let expected = run(&context, &commitments);
    let mut best = u128::MAX;
    for _ in 0..5 {
        let started = std::time::Instant::now();
        for _ in 0..200 {
            assert_eq!(run(&context, &commitments).queries, expected.queries);
        }
        best = best.min(started.elapsed().as_nanos() / 200);
    }
    eprintln!(
        "exploratory transcript replay: profile={} identity={} nanoseconds_per_transcript={best} tape_bytes=30920 statement_bytes={}",
        transcript_profile::profile().name(),
        transcript_profile::profile().id(),
        STATEMENT.len()
    );
}
