//! Held CPU-only outer-hash component experiment; not a proof suite or release API.
//!
//! This file is a test-only child of `privacy_engines::transparent_stark`.
//! Public synthetic rows have the native note width, but only 64 rows are used.
//! Every scheme retains its own digest bytes, transcript state and Merkle root.

use super::*;
use crate::privacy_engines::{aggregate_stark, ivm_private_note};
use fastpq_isi::{
    GoldilocksDigest384DomainPrefixV1, GoldilocksDigest384FrameV1, GoldilocksDigestDomainV1,
};
use sha3::{Digest, Sha3_384};
use std::{hint::black_box, time::Instant};

const SHA_FRAME: &[u8] = b"iroha:privacy:outer-sha3-384:experiment:v1\0";
const ROWS: usize = 64;
const NONCES: u64 = 4096;
const CHALLENGES: usize = 32;
const TARGET_BITS: u8 = 20;
const PAIRS: usize = 4;
const WORKERS: usize = 8;
// Exact private-note labels from ivm_private_note/stark.rs, bound in the packet.
const CONTEXT: TransparentStarkDigestContextV1 = TransparentStarkDigestContextV1::new(
    PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1,
    b"ivm-private-note-stark-profile-v1",
);
const LEAF: &[u8] = b"ivm-private-note-stark-base-leaf-v1";
const NODE: &[u8] = b"ivm-private-note-stark-base-node-v1";
const ROOT_LABEL: &[u8] = b"ivm-private-note-stark-base-root-v1";
const CHALLENGE_LABEL: &[u8] = b"ivm-private-note-stark-fri-beta-v1";

/// Raw bytes remain raw bytes even when they are not canonical field words.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ShaDigest([u8; 48]);

#[derive(Clone)]
struct ShaPrefix(Sha3_384);

fn byte_field(hash: &mut Sha3_384, tag: u8, bytes: &[u8]) -> Option<()> {
    let length = u32::try_from(bytes.len()).ok()?;
    hash.update([tag]);
    hash.update(length.to_be_bytes());
    hash.update(bytes);
    Some(())
}

impl ShaPrefix {
    // Cache only invariant fields through level, matching the Poseidon prefix scope.
    fn new(domain: GoldilocksDigestDomainV1<'_>) -> Option<Self> {
        let mut hash = Sha3_384::new();
        hash.update(SHA_FRAME);
        for (tag, bytes) in [
            (1, domain.catalog),
            (2, domain.protocol),
            (3, domain.profile),
            (4, domain.role),
            (5, domain.phase),
        ] {
            byte_field(&mut hash, tag, bytes)?;
        }
        hash.update([6]);
        hash.update(domain.level.to_be_bytes());
        Some(Self(hash))
    }

    fn hash_at(&self, index: u64, counter: u64, fields: &[&[u8]]) -> Option<ShaDigest> {
        let count = u32::try_from(fields.len()).ok()?;
        let mut hash = self.0.clone();
        hash.update([7]);
        hash.update(index.to_be_bytes());
        hash.update([8]);
        hash.update(counter.to_be_bytes());
        hash.update([9]);
        hash.update(count.to_be_bytes());
        for (index, field) in fields.iter().enumerate() {
            hash.update([10]);
            hash.update(u32::try_from(index).ok()?.to_be_bytes());
            hash.update(u32::try_from(field.len()).ok()?.to_be_bytes());
            hash.update(field);
        }
        Some(ShaDigest(hash.finalize().into()))
    }
}

fn sha_frame(domain: GoldilocksDigestDomainV1<'_>, fields: &[&[u8]]) -> ShaDigest {
    ShaPrefix::new(domain)
        .unwrap()
        .hash_at(domain.index, domain.counter, fields)
        .unwrap()
}

fn domain<'a>(
    catalog: &'a [u8; 32],
    role: &'a [u8],
    phase: &'a [u8],
    level: u64,
) -> GoldilocksDigestDomainV1<'a> {
    GoldilocksDigestDomainV1 {
        catalog,
        protocol: CONTEXT.protocol_label_v1(),
        profile: CONTEXT.profile,
        role,
        phase,
        level,
        index: 0,
        counter: 0,
    }
}

fn fp4_words(digest: ShaDigest) -> Option<[u64; 4]> {
    let words = core::array::from_fn(|index| {
        u64::from_be_bytes(digest.0[index * 8..index * 8 + 8].try_into().unwrap())
    });
    words
        .iter()
        .all(|word| *word < GOLDILOCKS_MODULUS_V1)
        .then_some(words)
}

fn leading_target(digest: ShaDigest, bits: u8) -> Option<bool> {
    if bits > 63 {
        return None;
    }
    Some(u64::from_be_bytes(digest.0[..8].try_into().unwrap()).leading_zeros() >= u32::from(bits))
}

#[derive(Clone, Copy)]
struct ShaTranscript {
    state: ShaDigest,
    counter: u64,
}

impl ShaTranscript {
    fn new(catalog: &[u8; 32], profile: ShaDigest, public: ShaDigest) -> Self {
        Self {
            state: sha_frame(
                domain(catalog, TRANSCRIPT_INIT_DOMAIN_V1, b"initialize", 0),
                &[b"StarkFriSha3_384Experiment", &profile.0, &public.0],
            ),
            counter: 0,
        }
    }

    fn absorb(&mut self, catalog: &[u8; 32], label: &[u8], fields: &[&[u8]]) {
        let message = sha_frame(
            GoldilocksDigestDomainV1 {
                counter: self.counter,
                ..domain(catalog, b"transcript-message", label, 0)
            },
            fields,
        );
        self.state = sha_frame(
            GoldilocksDigestDomainV1 {
                counter: self.counter,
                ..domain(catalog, TRANSCRIPT_ABSORB_DOMAIN_V1, label, 0)
            },
            &[&self.state.0, &message.0],
        );
        self.counter = 0;
    }

    // Reject a whole noncanonical tuple. Never reduce bytes modulo the field.
    // Accepted digest absorption and checked counter advancement mirror production ordering.
    fn challenge_with(
        &mut self,
        absorb: &ShaPrefix,
        mut oracle: impl FnMut(u64, u64, ShaDigest) -> ShaDigest,
    ) -> Option<[u64; 4]> {
        for attempt in 0..MAX_FIELD_REJECTION_ATTEMPTS_V1 {
            let digest = oracle(attempt, self.counter, self.state);
            if let Some(words) = fp4_words(digest) {
                let next = self.counter.checked_add(1)?;
                let state = absorb.hash_at(0, self.counter, &[&self.state.0, &digest.0])?;
                self.counter = next;
                self.state = state;
                return Some(words);
            }
        }
        None
    }

    fn sequence(
        &mut self,
        catalog: &[u8; 32],
        label: &[u8],
        count: usize,
    ) -> Option<Vec<[u64; 4]>> {
        if count == 0 {
            return Some(Vec::new());
        }
        if label.is_empty() || u16::try_from(label.len()).is_err() {
            return None;
        }
        let challenge = ShaPrefix::new(domain(
            catalog,
            TRANSCRIPT_FP4_CHALLENGE_DOMAIN_V1,
            label,
            0,
        ))?;
        let absorb = ShaPrefix::new(domain(catalog, TRANSCRIPT_ABSORB_DOMAIN_V1, label, 0))?;
        (0..count)
            .map(|_| {
                self.challenge_with(&absorb, |attempt, counter, state| {
                    challenge.hash_at(attempt, counter, &[&state.0]).unwrap()
                })
            })
            .collect()
    }
}

fn public_rows() -> Vec<Vec<GoldilocksFieldV1>> {
    (0..ROWS)
        .map(|row| {
            (0..ivm_private_note::PRIVATE_NOTE_BASE_WIDTH_V1)
                .map(|column| GoldilocksFieldV1((row * 1009 + column * 17) as u64))
                .collect()
        })
        .collect()
}

fn row_bytes(rows: &[Vec<GoldilocksFieldV1>]) -> Vec<Vec<u8>> {
    rows.iter()
        .map(|row| row.iter().flat_map(|value| value.0.to_be_bytes()).collect())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

// Only public experiment data is printed. Timings contain complete batches and include
// prefix setup, but exclude fixture construction, hex encoding and output formatting.
fn measure<T>(
    pair: usize,
    suite: &str,
    operation: &str,
    population: usize,
    run: impl FnOnce() -> T,
    fingerprint: impl FnOnce(&T) -> String,
) -> T {
    let started = Instant::now();
    let result = black_box(run());
    let elapsed = started.elapsed().as_nanos();
    println!(
        "OUTER_HASH_V1,{pair},{suite},{operation},{population},{WORKERS},{elapsed},{}",
        fingerprint(&result)
    );
    result
}

fn poseidon_run(pair: usize, catalog: &[u8; 32], rows: &[Vec<u8>]) {
    let width = u16::try_from(ivm_private_note::PRIVATE_NOTE_BASE_WIDTH_V1)
        .unwrap()
        .to_be_bytes();
    let group = 0_u16.to_be_bytes();
    let leaves = measure(
        pair,
        "poseidon6",
        "leaf_cached",
        ROWS,
        || {
            let prefix = GoldilocksDigest384DomainPrefixV1::new(domain(
                catalog,
                LEAF,
                b"vector-row-leaf",
                0,
            ))
            .unwrap();
            rows.par_iter()
                .enumerate()
                .map(|(index, row)| {
                    prefix
                        .hash_at_with_counter(index as u64, 0, &[&group, &width, row])
                        .unwrap()
                })
                .collect::<Vec<_>>()
        },
        |values| hex(&values[0].to_le_bytes()),
    );
    let root = measure(
        pair,
        "poseidon6",
        "tree_nodes_cached",
        ROWS - 1,
        || {
            let mut current = leaves;
            let mut level = 1;
            while current.len() > 1 {
                let prefix = GoldilocksDigest384DomainPrefixV1::new(domain(
                    catalog,
                    NODE,
                    MERKLE_NODE_PHASE_V1,
                    level,
                ))
                .unwrap();
                current = current
                    .par_chunks_exact(2)
                    .enumerate()
                    .map(|(index, pair)| {
                        prefix
                            .hash_at(
                                index as u64,
                                &[&pair[0].to_le_bytes(), &pair[1].to_le_bytes()],
                            )
                            .unwrap()
                    })
                    .collect();
                level += 1;
            }
            current[0]
        },
        |value| hex(&value.to_le_bytes()),
    );
    let seed = measure(
        pair,
        "poseidon6",
        "transcript_fp4",
        CHALLENGES,
        || {
            // Fixed comparison baseline, independent of the production privacy suite.
            let mut state = GoldilocksDigest384FrameV1::new(
                domain(catalog, TRANSCRIPT_INIT_DOMAIN_V1, b"initialize", 0),
                &[
                    b"StarkFriPoseidonX7Goldilocks6x64",
                    &root.to_le_bytes(),
                    &root.to_le_bytes(),
                ],
            )
            .unwrap()
            .hash();
            let message = GoldilocksDigest384FrameV1::new(
                domain(catalog, b"transcript-message", ROOT_LABEL, 0),
                &[&root.to_le_bytes()],
            )
            .unwrap()
            .hash();
            state = GoldilocksDigest384FrameV1::new(
                domain(catalog, TRANSCRIPT_ABSORB_DOMAIN_V1, ROOT_LABEL, 0),
                &[&state.to_le_bytes(), &message.to_le_bytes()],
            )
            .unwrap()
            .hash();
            let challenge = GoldilocksDigest384DomainPrefixV1::new(domain(
                catalog,
                TRANSCRIPT_FP4_CHALLENGE_DOMAIN_V1,
                CHALLENGE_LABEL,
                0,
            ))
            .unwrap();
            let absorb = GoldilocksDigest384DomainPrefixV1::new(domain(
                catalog,
                TRANSCRIPT_ABSORB_DOMAIN_V1,
                CHALLENGE_LABEL,
                0,
            ))
            .unwrap();
            for counter in 0..CHALLENGES as u64 {
                let candidate = challenge
                    .hash_at_with_counter(0, counter, &[&state.to_le_bytes()])
                    .unwrap();
                black_box(
                    GoldilocksFp4V1::canonical(candidate.words()[..4].try_into().unwrap()).unwrap(),
                );
                state = absorb
                    .hash_at_with_counter(
                        0,
                        counter,
                        &[&state.to_le_bytes(), &candidate.to_le_bytes()],
                    )
                    .unwrap();
            }
            state
        },
        |value| hex(&value.to_le_bytes()),
    );
    measure(
        pair,
        "poseidon6",
        "grinding_fixed_attempts",
        NONCES as usize,
        || {
            let bytes = seed.to_le_bytes();
            let fields: &[&[u8]] = &[&bytes];
            let frame = GoldilocksDigest384FrameV1::new(
                domain(catalog, GRINDING_DOMAIN_V1, b"proof-of-work-nonce", 0),
                fields,
            )
            .unwrap();
            let predicate = frame.indexed_predicate_v1();
            (0..NONCES)
                .into_par_iter()
                .map(|nonce| u64::from(predicate.matches_index_v1(nonce, TARGET_BITS).unwrap()))
                .sum::<u64>()
        },
        |hits| hits.to_string(),
    );
}

fn sha_run(pair: usize, catalog: &[u8; 32], rows: &[Vec<u8>]) {
    let width = u16::try_from(ivm_private_note::PRIVATE_NOTE_BASE_WIDTH_V1)
        .unwrap()
        .to_be_bytes();
    let group = 0_u16.to_be_bytes();
    let leaves = measure(
        pair,
        "sha3_384",
        "leaf_cached",
        ROWS,
        || {
            let prefix = ShaPrefix::new(domain(catalog, LEAF, b"vector-row-leaf", 0)).unwrap();
            rows.par_iter()
                .enumerate()
                .map(|(index, row)| {
                    prefix
                        .hash_at(index as u64, 0, &[&group, &width, row])
                        .unwrap()
                })
                .collect::<Vec<_>>()
        },
        |values| hex(&values[0].0),
    );
    let root = measure(
        pair,
        "sha3_384",
        "tree_nodes_cached",
        ROWS - 1,
        || {
            let mut current = leaves;
            let mut level = 1;
            while current.len() > 1 {
                let prefix =
                    ShaPrefix::new(domain(catalog, NODE, MERKLE_NODE_PHASE_V1, level)).unwrap();
                current = current
                    .par_chunks_exact(2)
                    .enumerate()
                    .map(|(index, pair)| {
                        prefix
                            .hash_at(index as u64, 0, &[&pair[0].0, &pair[1].0])
                            .unwrap()
                    })
                    .collect();
                level += 1;
            }
            current[0]
        },
        |value| hex(&value.0),
    );
    let seed = measure(
        pair,
        "sha3_384",
        "transcript_fp4",
        CHALLENGES,
        || {
            // Root bytes occupy profile/public-digest fixture slots; these are not real statement digests.
            let mut transcript = ShaTranscript::new(catalog, root, root);
            transcript.absorb(catalog, ROOT_LABEL, &[&root.0]);
            black_box(
                transcript
                    .sequence(catalog, CHALLENGE_LABEL, CHALLENGES)
                    .unwrap(),
            );
            transcript.state
        },
        |value| hex(&value.0),
    );
    measure(
        pair,
        "sha3_384",
        "grinding_fixed_attempts",
        NONCES as usize,
        || {
            let prefix = ShaPrefix::new(domain(
                catalog,
                GRINDING_DOMAIN_V1,
                b"proof-of-work-nonce",
                0,
            ))
            .unwrap();
            (0..NONCES)
                .into_par_iter()
                .map(|nonce| {
                    u64::from(
                        leading_target(prefix.hash_at(nonce, 0, &[&seed.0]).unwrap(), TARGET_BITS)
                            .unwrap(),
                    )
                })
                .sum::<u64>()
        },
        |hits| hits.to_string(),
    );
}

#[test]
fn production_frames_and_cached_digest_agree() {
    // The production scheme now has its own reviewed exact framing. Experimental
    // comparison schemes below retain their original distinct known-answer vectors.
    use crate::privacy_engines::privacy_outer_hash::{
        PrivacyOuterDomainPrefixV1, PrivacyOuterFrameV1,
    };
    let catalog = CONTEXT.catalog_v1();
    let rows = public_rows();
    let bytes = row_bytes(&rows);
    let group = 0_u16.to_be_bytes();
    let width = u16::try_from(rows[0].len()).unwrap().to_be_bytes();
    let prefix = PrivacyOuterDomainPrefixV1::new(
        CONTEXT
            .domain_v1(&catalog, LEAF, b"vector-row-leaf", 0, 0, 0)
            .unwrap(),
    )
    .unwrap();
    let leaves: Vec<_> = (0..2)
        .map(|index| {
            let actual =
                aggregate_stark::row_leaf_hash_v1(CONTEXT, LEAF, 0, index, &rows[index]).unwrap();
            assert_eq!(
                Some(actual),
                prefix.hash_at_with_counter(index as u64, 0, &[&group, &width, &bytes[index]])
            );
            actual
        })
        .collect();
    let node = PrivacyOuterDomainPrefixV1::new(
        CONTEXT
            .domain_v1(&catalog, NODE, MERKLE_NODE_PHASE_V1, 1, 0, 0)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        Some(privacy_outer_merkle_node_v1(CONTEXT, NODE, 1, 0, leaves[0], leaves[1]).unwrap()),
        node.hash_at_with_counter(0, 0, &[leaves[0].as_bytes(), leaves[1].as_bytes()])
    );
    let fields: &[&[u8]] = &[leaves[0].as_bytes()];
    let frame_domain = CONTEXT
        .domain_v1(
            &catalog,
            GRINDING_DOMAIN_V1,
            b"proof-of-work-nonce",
            0,
            0,
            0,
        )
        .unwrap();
    let prefix = PrivacyOuterDomainPrefixV1::new(frame_domain).unwrap();
    for nonce in [0, 1, 4095, u64::MAX] {
        let full = PrivacyOuterFrameV1::new(
            crate::privacy_engines::privacy_outer_hash::PrivacyOuterDomainV1 {
                proof_scope: None,
                index: nonce,
                ..frame_domain
            },
            fields,
        )
        .unwrap()
        .hash();
        assert_eq!(prefix.hash_at_with_counter(nonce, 0, fields), Some(full));
        let matches = u64::from_be_bytes(full.as_bytes()[..8].try_into().unwrap()).leading_zeros()
            >= u32::from(TARGET_BITS);
        assert_eq!(
            verify_grinding_nonce_v1(CONTEXT, &leaves[0], TARGET_BITS, nonce).is_ok(),
            matches
        );
    }
}

#[test]
fn sha3_independent_vectors_and_field_boundaries() {
    assert_eq!(
        hex(&Sha3_384::digest(b"")),
        "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    );
    let kat = GoldilocksDigestDomainV1 {
        catalog: b"catalog",
        protocol: b"protocol",
        profile: b"profile",
        role: b"leaf",
        phase: b"phase",
        level: 3,
        index: 7,
        counter: 11,
    };
    assert_eq!(
        hex(&sha_frame(kat, &[b"", b"abc", &[0, 255]]).0),
        "2ac95d657238fe062245c1a40a5b0a8fe498c17eebc1bfbae16b08e5d9df4f34808bae60a7882d87249f83d85163de58"
    );
    assert_ne!(
        sha_frame(kat, &[b"ab", b"c"]),
        sha_frame(kat, &[b"a", b"bc"])
    );
    assert_ne!(sha_frame(kat, &[b""]), sha_frame(kat, &[]));
    assert_ne!(
        sha_frame(kat, &[]),
        sha_frame(GoldilocksDigestDomainV1 { counter: 12, ..kat }, &[])
    );
    assert_eq!(fp4_words(ShaDigest([0; 48])), Some([0; 4]));
    let mut raw = [0_u8; 48];
    raw[..8].copy_from_slice(&(GOLDILOCKS_MODULUS_V1 - 1).to_be_bytes());
    assert_eq!(
        fp4_words(ShaDigest(raw)).unwrap()[0],
        GOLDILOCKS_MODULUS_V1 - 1
    );
    raw[..8].copy_from_slice(&GOLDILOCKS_MODULUS_V1.to_be_bytes());
    assert_eq!(fp4_words(ShaDigest(raw)), None);
    assert_eq!(fp4_words(ShaDigest([255; 48])), None);
    assert_eq!(leading_target(ShaDigest([0; 48]), 63), Some(true));
    assert_eq!(leading_target(ShaDigest([0; 48]), 64), None);
    assert_eq!(leading_target(ShaDigest([255; 48]), 20), Some(false));
}

#[test]
fn sha3_rejection_counter_and_absorption_are_bounded() {
    let catalog = CONTEXT.catalog_v1();
    let prefix = ShaPrefix::new(domain(
        &catalog,
        TRANSCRIPT_ABSORB_DOMAIN_V1,
        CHALLENGE_LABEL,
        0,
    ))
    .unwrap();
    let initial = ShaTranscript::new(&catalog, ShaDigest([0; 48]), ShaDigest([0; 48]));
    let mut transcript = initial;
    let mut calls = 0;
    let words = transcript.challenge_with(&prefix, |attempt, counter, state| {
        calls += 1;
        assert_eq!(counter, 0);
        assert_eq!(state, initial.state);
        if attempt == 0 {
            ShaDigest([255; 48])
        } else {
            ShaDigest([0; 48])
        }
    });
    assert_eq!(words, Some([0; 4]));
    assert_eq!(calls, 2);
    assert_eq!(transcript.counter, 1);
    assert_eq!(
        transcript.state,
        prefix.hash_at(0, 0, &[&initial.state.0, &[0; 48]]).unwrap()
    );
    let mut failed = initial;
    calls = 0;
    assert!(
        failed
            .challenge_with(&prefix, |_, _, _| {
                calls += 1;
                ShaDigest([255; 48])
            })
            .is_none()
    );
    assert_eq!(calls, MAX_FIELD_REJECTION_ATTEMPTS_V1);
    assert_eq!(failed.state, initial.state);
    assert_eq!(failed.counter, 0);
    failed.counter = u64::MAX;
    assert!(
        failed
            .challenge_with(&prefix, |_, _, _| ShaDigest([0; 48]))
            .is_none()
    );
    assert_eq!(failed.counter, u64::MAX);
    assert_eq!(failed.state, initial.state);
    assert_eq!(failed.sequence(&catalog, b"", 0), Some(Vec::new()));
    assert!(failed.sequence(&catalog, b"", 1).is_none());
}

#[test]
#[ignore = "explicit isolated outer-hash component experiment; no proof is constructed"]
fn outer_hash_component_pairs() {
    assert_eq!(
        TARGET_BITS,
        crate::privacy_engines::proof_managed_note_stark::PROOF_MANAGED_NOTE_GRINDING_BITS_V1
    );
    assert_eq!(ivm_private_note::PRIVATE_NOTE_BASE_WIDTH_V1, 556);
    let rows = row_bytes(&public_rows());
    let catalog = CONTEXT.catalog_v1();
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(WORKERS)
        .build()
        .unwrap();
    println!(
        "OUTER_HASH_CONFIG_V1,rows={ROWS},width=556,nonces={NONCES},target={TARGET_BITS},challenges={CHALLENGES},pairs={PAIRS},workers={WORKERS},catalog={}",
        hex(&catalog)
    );
    // Pair zero is first use and is reported separately, not silently called steady-state.
    pool.install(|| {
        for pair in 0..PAIRS {
            if pair % 2 == 0 {
                poseidon_run(pair, &catalog, &rows);
                sha_run(pair, &catalog, &rows);
            } else {
                sha_run(pair, &catalog, &rows);
                poseidon_run(pair, &catalog, &rows);
            }
        }
    });
}
