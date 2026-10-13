//! A complete seeded proof under the frozen transcript, and its binding.
//!
//! The proof is built by the same producer as every artifact, from fixed test
//! entropy. Its bytes are pinned in `fixtures/fastpq/q77-frozen-transcript-proof.json`:
//! a change of the transcript, of the profile descriptor or of the wire changes
//! the digest, and the pin is then replaced deliberately. The bounded verifier
//! must reject the proof under every changed, reordered or omitted element it
//! binds, including each opening it authenticates and each index it derives.
//!
//! Building the proof is expensive, so it is done by one test that retains the
//! bytes under `target/fastpq-production-validation`; the binding test reads
//! the retained bytes named by the pin and proves nothing. A retained file is
//! an untracked observation; only the tracked pin is a golden.
//!
//! This shows conformance with the frozen binding. It shows no soundness level.

use fastpq_isi::{
    keccak256::Sha3_256V1,
    semantic_profile::{SemanticProfileOwnedValueV1 as Owned, SemanticProfileV1},
};
use iroha_data_model::fastpq::FastpqCommitmentV1 as WireDigest;

use super::{retirement_tests::fixture, *};
use crate::{
    backend::{
        compact_protocol::FixedAir,
        compact_sha3::Context as FramingContext,
        compact_transfer_air::CompactTransferAir,
        deep_binding::Context,
        deep_engine,
        deep_proof::{self, DeepProof, RowValues},
        transcript_profile::{self, CONSTRUCTION, FRAMING_VERSION},
    },
    field::GoldilocksFp4V1 as F,
};

/// Fixed public test entropy of the pinned proof.
const SEED: u64 = 0x0048_3200_7707;
/// Statement context tag of the pinned proof.
const TAG: &[u8] = b"frozen transcript proof-byte golden";
/// Tracked proof-byte golden of the frozen transcript.
const PIN: &str = "fixtures/fastpq/q77-frozen-transcript-proof.json";

/// Tracked pin of the seeded proof: what was proved and the digest of its bytes.
#[derive(Debug, PartialEq, Eq, norito::derive::JsonSerialize, norito::derive::JsonDeserialize)]
struct ProofPin {
    /// Name of the frozen transcript profile the proof was built under.
    profile: String,
    /// Identity of that profile.
    profile_identity: String,
    /// Test entropy seed, as a decimal string so every `u64` is exact.
    seed: String,
    /// Statement context tag, hex.
    tag_hex: String,
    /// Exact canonical frame length.
    bytes: usize,
    /// SHA3-256 of the canonical frame.
    sha3_256: String,
}

fn workspace() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn retained_path(digest: &str) -> std::path::PathBuf {
    workspace()
        .join("target/fastpq-production-validation")
        .join(format!("frozen-transcript-proof-{digest}.bin"))
}

fn sha3(bytes: &[u8]) -> String {
    let mut hash = Sha3_256V1::new();
    hash.update(bytes);
    hex::encode(hash.finalize().into_bytes())
}

fn observed_pin(bytes: &[u8]) -> ProofPin {
    let profile = transcript_profile::profile();
    ProofPin {
        profile: profile.name().to_owned(),
        profile_identity: profile.id().to_string(),
        seed: SEED.to_string(),
        tag_hex: hex::encode(TAG),
        bytes: bytes.len(),
        sha3_256: sha3(bytes),
    }
}

/// Build the seeded proof, check it, and retain its bytes for the binding test.
///
/// The output is an observation: it prints the pin that
/// `fixtures/fastpq/q77-frozen-transcript-proof.json` holds when the bytes are
/// unchanged, and never writes the tracked pin itself.
#[test]
#[ignore = "builds one complete q77 proof under the frozen transcript and retains it; run with --release"]
fn seeded_proof_under_the_frozen_transcript_is_built_and_retained() {
    let (statement, witness) = fixture();
    let relation = CompactTransferAir::new(&statement, Some(TAG)).unwrap();
    let source = OwnedTraceSource::from_rows(witness.rows()).unwrap();
    drop(witness);
    let bytes = prove(&relation, source, SEED).unwrap();
    let accepted =
        deep_engine::verify_committed(&relation, &bytes, engine_verification_limits()).unwrap();
    assert_eq!(accepted.work().verifier_messages, 10);
    assert_eq!(accepted.work().proof_bytes, bytes.len());
    let pin = observed_pin(&bytes);
    let path = retained_path(&pin.sha3_256);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, &bytes).unwrap();
    eprintln!("frozen_proof_pin={}", norito::json::to_json(&pin).unwrap());
    eprintln!("retained frozen transcript proof at {}", path.display());
}

fn flipped(digest: WireDigest) -> WireDigest {
    let mut bytes = *digest.as_bytes();
    bytes[17] ^= 0x10;
    WireDigest::from_bytes(bytes)
}

fn bump(value: F) -> F {
    let mut words = value.coefficients();
    words[2] ^= 1;
    F::new(words).unwrap()
}

#[test]
#[ignore = "reads the retained seeded proof named by the tracked pin; run the producer first, with --release"]
fn a_real_proof_fails_under_every_changed_reordered_or_omitted_bound_element() {
    let pin: ProofPin = norito::json::from_slice(
        &std::fs::read(workspace().join(PIN)).expect("tracked proof-byte golden"),
    )
    .unwrap();
    let bytes = std::fs::read(retained_path(&pin.sha3_256))
        .expect("retain the seeded proof with the producer test first");
    // Proof-byte golden of the frozen transcript: the retained bytes are exactly
    // the pinned ones, built under the current profile identity.
    assert_eq!(
        pin,
        observed_pin(&bytes),
        "the seeded proof or the frozen profile changed; replace the pin deliberately"
    );
    let (statement, witness) = fixture();
    drop(witness);
    let relation = CompactTransferAir::new(&statement, Some(TAG)).unwrap();
    let limits = engine_verification_limits();
    let accepted = deep_engine::verify_committed(&relation, &bytes, limits).unwrap();
    assert_eq!(accepted.work().verifier_messages, 10);
    assert_eq!(accepted.work().terminal_values, 128);
    assert_eq!(accepted.work().proof_bytes, pin.bytes);

    let proof = deep_proof::decode(&bytes, deep_proof::MAX_FRAME_BYTES).unwrap();
    assert_eq!(norito::encode_canonical(&proof).unwrap(), bytes);
    let rejected = |changed: &DeepProof, what: &str| {
        let encoded = norito::encode_canonical(changed).unwrap();
        assert_ne!(encoded, bytes, "{what}: the mutation changed nothing");
        assert!(
            deep_engine::verify_committed(&relation, &encoded, limits).is_err(),
            "{what}: the proof still verifies"
        );
    };
    let with = |mutate: &dyn Fn(&mut DeepProof), what: &str| {
        let mut changed = proof.clone();
        mutate(&mut changed);
        rejected(&changed, what);
    };

    // Changed: every committed root.
    with(&|p| p.row_root = flipped(p.row_root), "row root");
    with(
        &|p| p.quotient_root = flipped(p.quotient_root),
        "quotient root",
    );
    for layer in 0..6 {
        with(
            &|p| p.fri_roots[layer] = flipped(p.fri_roots[layer]),
            &format!("FRI root {layer}"),
        );
    }
    // Changed: out-of-domain answers, first and last of each group.
    for index in [0, 150, 300] {
        with(
            &|p| p.ood.current[index] = bump(p.ood.current[index]),
            &format!("current-row answer {index}"),
        );
        with(
            &|p| p.ood.next[index] = bump(p.ood.next[index]),
            &format!("next-row answer {index}"),
        );
    }
    for half in 0..2 {
        with(
            &|p| p.ood.quotient[half] = bump(p.ood.quotient[half]),
            &format!("quotient answer {half}"),
        );
    }
    // Changed: every kind of authenticated opening and every index.
    let last_row = proof.rows.len() - 1;
    for row in [0, last_row] {
        for column in [0, 300] {
            with(
                &|p| {
                    let mut values = p.rows[row].values.to_vec();
                    values[column] ^= 1;
                    p.rows[row].values = RowValues::new(values).unwrap();
                },
                &format!("opened row {row} column {column}"),
            );
        }
        with(&|p| p.rows[row].index ^= 1, &format!("row index {row}"));
        with(
            &|p| p.quotients[row].low = bump(p.quotients[row].low),
            &format!("low quotient opening {row}"),
        );
        with(
            &|p| p.quotients[row].high = bump(p.quotients[row].high),
            &format!("high quotient opening {row}"),
        );
        with(
            &|p| p.quotients[row].composition_mask = bump(p.quotients[row].composition_mask),
            &format!("composition mask opening {row}"),
        );
        with(
            &|p| p.quotients[row].index ^= 1,
            &format!("quotient index {row}"),
        );
    }
    with(
        &|p| p.row_siblings[0] = flipped(p.row_siblings[0]),
        "row sibling",
    );
    with(
        &|p| {
            let last = p.quotient_siblings.len() - 1;
            p.quotient_siblings[last] = flipped(p.quotient_siblings[last]);
        },
        "quotient sibling",
    );
    for round in 0..5 {
        with(
            &|p| p.rounds[round].groups[0].values[0] = bump(p.rounds[round].groups[0].values[0]),
            &format!("fiber value of round {round}"),
        );
        with(
            &|p| p.rounds[round].groups[0].index ^= 1,
            &format!("fiber index of round {round}"),
        );
        if !proof.rounds[round].siblings.is_empty() {
            with(
                &|p| p.rounds[round].siblings[0] = flipped(p.rounds[round].siblings[0]),
                &format!("fiber sibling of round {round}"),
            );
        }
    }
    for index in [0, 1, 127] {
        with(
            &|p| p.terminal[index] = bump(p.terminal[index]),
            &format!("terminal value {index}"),
        );
    }

    // Reordered.
    with(&|p| p.fri_roots.swap(0, 1), "FRI roots exchanged");
    with(
        &|p| core::mem::swap(&mut p.row_root, &mut p.quotient_root),
        "row and quotient roots exchanged",
    );
    with(
        &|p| core::mem::swap(&mut p.ood.current, &mut p.ood.next),
        "out-of-domain rows exchanged",
    );
    with(&|p| p.ood.quotient.swap(0, 1), "quotient answers exchanged");
    with(&|p| p.rows.swap(0, 1), "opened rows exchanged");
    with(&|p| p.quotients.swap(0, 1), "quotient openings exchanged");
    with(&|p| p.row_siblings.swap(0, 1), "row siblings exchanged");
    with(&|p| p.rounds.swap(0, 1), "FRI rounds exchanged");
    with(&|p| p.rounds[0].groups.swap(0, 1), "fibers exchanged");
    with(&|p| p.terminal.swap(0, 127), "terminal values exchanged");
    with(
        &|p| core::mem::swap(&mut p.row_siblings, &mut p.quotient_siblings),
        "sibling frontiers exchanged",
    );

    // Omitted and added.
    with(
        &|p| {
            p.fri_roots.pop();
        },
        "omitted terminal root",
    );
    with(
        &|p| {
            p.ood.current.pop();
        },
        "omitted current-row answer",
    );
    with(
        &|p| {
            p.ood.quotient.pop();
        },
        "omitted quotient answer",
    );
    with(
        &|p| {
            p.rows.pop();
        },
        "omitted opened row",
    );
    with(
        &|p| {
            p.quotients.pop();
        },
        "omitted quotient opening",
    );
    with(
        &|p| {
            p.row_siblings.pop();
        },
        "omitted row sibling",
    );
    with(
        &|p| {
            p.rounds.pop();
        },
        "omitted FRI round",
    );
    with(
        &|p| {
            p.rounds[0].groups.pop();
        },
        "omitted fiber",
    );
    with(
        &|p| {
            p.terminal.pop();
        },
        "omitted terminal value",
    );
    with(
        &|p| {
            let extra = p.rows[0].clone();
            p.rows.push(extra);
        },
        "added opened row",
    );
    with(
        &|p| {
            let extra = p.row_siblings[0];
            p.row_siblings.push(extra);
        },
        "added row sibling",
    );
    with(
        &|p| {
            let extra = p.terminal[0];
            p.terminal.push(extra);
        },
        "added terminal value",
    );

    // Another statement, another relation tag, and a truncated frame.
    let other = CompactTransferAir::new(&statement, Some(b"another statement context")).unwrap();
    assert!(deep_engine::verify_committed(&other, &bytes, limits).is_err());
    assert!(deep_engine::verify_committed(&relation, &bytes[..bytes.len() - 1], limits).is_err());

    // The same proof under any other profile descriptor, construction name,
    // framing version or catalog does not verify.
    let profile = transcript_profile::profile();
    let catalog = fastpq_isi::FASTPQ_CATALOG_V1.as_bytes();
    let under = |version: u16, catalog: &[u8], construction: &[u8], descriptor: &[u8]| {
        let binding = Context::with_prefix_for_test(
            relation.schema().identity,
            relation.statement_bytes(),
            |context| {
                FramingContext::with_prefix_for_test(
                    version,
                    catalog,
                    construction,
                    descriptor,
                    context,
                )
            },
        )
        .unwrap();
        deep_engine::verify_under_binding_for_test(&relation, &bytes, &binding)
    };
    assert_eq!(
        under(
            FRAMING_VERSION,
            catalog,
            CONSTRUCTION.as_bytes(),
            profile.as_bytes()
        )
        .unwrap(),
        accepted.work(),
        "the test hook with the frozen parts is the production verifier"
    );
    assert!(
        under(
            FRAMING_VERSION + 1,
            catalog,
            CONSTRUCTION.as_bytes(),
            profile.as_bytes()
        )
        .is_err()
    );
    assert!(
        under(
            FRAMING_VERSION,
            b"another-catalog",
            CONSTRUCTION.as_bytes(),
            profile.as_bytes()
        )
        .is_err()
    );
    assert!(
        under(
            FRAMING_VERSION,
            catalog,
            b"fastpq-state-transition-stark-v1",
            profile.as_bytes()
        )
        .is_err()
    );
    assert!(
        under(
            FRAMING_VERSION,
            catalog,
            CONSTRUCTION.as_bytes(),
            profile.id().as_bytes()
        )
        .is_err()
    );
    let parameters = profile.parameters();
    for index in 0..parameters.len() {
        let mut changed = parameters.clone();
        changed[index].1 = match &parameters[index].1 {
            Owned::U64(number) => Owned::U64(number ^ 1),
            Owned::Text(label) => Owned::Text(format!("{label}x")),
            Owned::Bytes(opaque) => Owned::Bytes([opaque.as_slice(), &[0]].concat()),
            Owned::U64List(values) => {
                let mut values = values.clone();
                values[0] ^= 1;
                Owned::U64List(values)
            }
        };
        let mut omitted = parameters.clone();
        omitted.remove(index);
        for (what, list) in [("changed", changed), ("omitted", omitted)] {
            let borrowed: Vec<_> = list
                .iter()
                .map(|(key, value)| (key.as_str(), value.as_value()))
                .collect();
            let descriptor =
                SemanticProfileV1::new(profile.kind(), profile.name(), &borrowed).unwrap();
            assert!(
                under(
                    FRAMING_VERSION,
                    catalog,
                    CONSTRUCTION.as_bytes(),
                    descriptor.as_bytes()
                )
                .is_err(),
                "the proof verifies with `{}` {what}",
                parameters[index].0
            );
        }
    }
}
