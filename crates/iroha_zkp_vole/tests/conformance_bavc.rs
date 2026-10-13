//! BAVC conformance against the official FAEST v3.0.2 vectors (`bavc_tvs`), which
//! the upstream `tests/bavc.cpp` checks for all twelve parameter sets, and
//! black-box tests of commit, open and reconstruct on the standard rows.
//!
//! Upstream inputs that are not in the fixture: `iv` is 16 zero bytes and the root
//! seed is the first `lambda / 8` bytes of `00 01 02 .. 1f`.

mod common;

use std::thread;

use common::{Fixture, hash_array};
use iroha_zkp_vole::{
    bavc::{
        BavcError, Input, LeafScheme, commit, decode_challenge, decommitment_bytes, leaf_commit,
        opening_nodes, position_in_tree, reconstruct,
    },
    field::{Gf128, Gf192, Gf256},
    hash::Xof,
    params::{FAEST_PARAMETER_SETS, FaestParams, SecurityLevel, VoleParams},
    prg::prg,
    universal_hash::leaf_hash_bytes,
};

const ZERO_IV: [u8; 16] = [0; 16];
const OTHER_IV: [u8; 16] = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xff,
];

/// The upstream root key buffer, cut to `lambda / 8` bytes.
fn root_key(params: &VoleParams) -> Vec<u8> {
    (0u8..32).take(params.lambda().bytes()).collect()
}

/// The fixture namespace of a set: `FAEST-EM-128s` is `FAEST_EM_128S`.
fn fixture_name(set: &FaestParams) -> String {
    set.name().to_uppercase().replace('-', "_")
}

/// Run `check` on every item in its own thread; a failure in any fails the test.
fn in_parallel<T: Sync>(items: &[T], check: impl Fn(&T) + Sync) {
    thread::scope(|scope| {
        for item in items {
            let check = &check;
            scope.spawn(move || check(item));
        }
    });
}

/// A custom row that is none of the standard ones: `lambda = 256`, `tau = 100`,
/// `k = 3`, `tau_1 = 48`, 592 leaves. About half of all patterns need more than
/// its `T_open = 193` node keys.
fn custom_row(n_leafcom: usize) -> VoleParams {
    VoleParams::new(SecurityLevel::L256, 100, 8, 193, n_leafcom, 7, 704).expect("valid row")
}

fn standard_and_custom_rows() -> Vec<(String, VoleParams)> {
    let mut rows: Vec<(String, VoleParams)> = FAEST_PARAMETER_SETS
        .iter()
        .map(|set| (set.name().to_owned(), *set.vole()))
        .collect();
    rows.push(("custom hashed".to_owned(), custom_row(3)));
    rows.push(("custom direct".to_owned(), custom_row(2)));
    rows
}

/// A deterministic sequence of valid patterns (64-bit LCG, high bits).
struct Patterns {
    state: u64,
}

impl Patterns {
    fn next(&mut self, params: &VoleParams) -> Vec<u16> {
        (0..params.tau())
            .map(|vector| {
                self.state = self
                    .state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                let leaves = u64::try_from(params.leaves_of(vector).expect("vector below tau"))
                    .expect("small");
                u16::try_from((self.state >> 33) % leaves).expect("index fits")
            })
            .collect()
    }

    /// The first pattern whose opening does (`fits`) or does not fit in `T_open`.
    fn find(&mut self, params: &VoleParams, fits: bool) -> Vec<u16> {
        for _ in 0..4096 {
            let hidden = self.next(params);
            let nodes = opening_nodes(params, &hidden).expect("valid pattern");
            if (nodes <= params.t_open()) == fits {
                return hidden;
            }
        }
        panic!("no pattern with fits = {fits} found");
    }
}

/// All entries of one fixture namespace.
struct Vector {
    set: FaestParams,
    h: Vec<u8>,
    hashed_k: Vec<u8>,
    hashed_sd: Vec<u8>,
    i_delta: Vec<u16>,
    hashed_decom_i: Vec<u8>,
    hashed_rec_sd: Vec<u8>,
    leaf_commit_key: Vec<u8>,
    leaf_commit_iv: [u8; 16],
    leaf_commit_uhash: Vec<u8>,
    tweak: u32,
    leaf_commit_expected_sd: Vec<u8>,
    leaf_commit_expected_com: Vec<u8>,
}

fn vectors(fixture: &Fixture) -> Vec<Vector> {
    FAEST_PARAMETER_SETS
        .iter()
        .map(|set| {
            let name = |entry: &str| format!("bavc_tvs.{}.{entry}", fixture_name(set));
            Vector {
                set: *set,
                h: fixture.bytes(&name("h")),
                hashed_k: fixture.bytes(&name("hashed_k")),
                hashed_sd: fixture.bytes(&name("hashed_sd")),
                i_delta: fixture.u16_list(&name("i_delta")),
                hashed_decom_i: fixture.bytes(&name("hashed_decom_i")),
                hashed_rec_sd: fixture.bytes(&name("hashed_rec_sd")),
                leaf_commit_key: fixture.bytes(&name("leaf_commit_key")),
                leaf_commit_iv: fixture
                    .bytes(&name("leaf_commit_iv"))
                    .try_into()
                    .expect("16-byte iv"),
                // Upstream emits no `uhash` for the Even-Mansour sets.
                leaf_commit_uhash: match LeafScheme::of(set.vole()) {
                    LeafScheme::Hashed => fixture.bytes(&name("leaf_commit_uhash")),
                    LeafScheme::Direct => Vec::new(),
                },
                tweak: u32::try_from(fixture.integer(&name("tweak"))).expect("32-bit tweak"),
                leaf_commit_expected_sd: fixture.bytes(&name("leaf_commit_expected_sd")),
                leaf_commit_expected_com: fixture.bytes(&name("leaf_commit_expected_com")),
            }
        })
        .collect()
}

/// The upstream `test_vc_tv` on one parameter set, with every buffer compared.
fn check_tree_vector(tv: &Vector) {
    let name = tv.set.name();
    let params = tv.set.vole();
    let lb = params.lambda().bytes();
    let leaves = params.leaves();

    let commitment = commit(params, &root_key(params), &ZERO_IV).expect("valid call");
    assert_eq!(commitment.commitment(), tv.h, "{name}: h");

    // `vc.k`: the `2L - 1` node keys in heap order.
    let keys = commitment.node_keys();
    assert_eq!(keys.len(), (2 * leaves - 1) * lb, "{name}");
    assert_eq!(hash_array(keys)[..], tv.hashed_k[..], "{name}: hashed_k");

    // `vc.sd`: the `L` leaf seeds, vector after vector.
    let all_seeds: Vec<u8> = (0..params.tau())
        .flat_map(|vector| commitment.seeds(vector).expect("vector below tau").to_vec())
        .collect();
    assert_eq!(all_seeds.len(), leaves * lb, "{name}");
    assert_eq!(
        hash_array(&all_seeds)[..],
        tv.hashed_sd[..],
        "{name}: hashed_sd"
    );

    // The whole zero-padded opening.
    assert_eq!(tv.i_delta.len(), params.tau(), "{name}");
    let decommitment = commitment.open(&tv.i_delta).expect("upstream opened it");
    assert_eq!(
        decommitment.len(),
        (params.n_leafcom() * params.tau() + params.t_open()) * lb,
        "{name}"
    );
    assert_eq!(decommitment.len(), decommitment_bytes(params), "{name}");
    assert_eq!(
        hash_array(&decommitment)[..],
        tv.hashed_decom_i[..],
        "{name}: hashed_decom_i"
    );

    // `vc_rec.h` and `vc_rec.s`: the `L - tau` revealed seeds, vector after vector,
    // each vector in index order without its hidden entry.
    let rebuilt = reconstruct(params, &decommitment, &tv.i_delta, &ZERO_IV).expect("valid");
    assert_eq!(rebuilt.commitment(), tv.h, "{name}: reconstructed h");
    let mut revealed = Vec::with_capacity((leaves - params.tau()) * lb);
    for (vector, &delta) in tv.i_delta.iter().enumerate() {
        assert_eq!(rebuilt.hidden_index(vector), Some(delta), "{name}");
        let seeds = rebuilt.seeds(vector).expect("vector below tau");
        let committed = commitment.seeds(vector).expect("vector below tau");
        for (index, (seed, original)) in seeds.chunks(lb).zip(committed.chunks(lb)).enumerate() {
            if index == usize::from(delta) {
                assert!(seed.iter().all(|&byte| byte == 0), "{name}: hidden slot");
            } else {
                assert_eq!(seed, original, "{name}: seed {vector},{index}");
                revealed.extend_from_slice(seed);
            }
        }
    }
    assert_eq!(revealed.len(), (leaves - params.tau()) * lb, "{name}");
    assert_eq!(
        hash_array(&revealed)[..],
        tv.hashed_rec_sd[..],
        "{name}: hashed_rec_sd"
    );
}

/// The upstream `leaf_commit(sd, com, key, iv, tweak, uhash)` vector of one set.
fn check_leaf_vector(tv: &Vector) {
    let name = tv.set.name();
    let params = tv.set.vole();
    let lb = params.lambda().bytes();
    assert_eq!(tv.leaf_commit_key.len(), lb, "{name}");
    assert_eq!(
        tv.leaf_commit_uhash.len(),
        LeafScheme::of(params).hash_key_bytes(params.lambda()),
        "{name}"
    );
    let mut sd = vec![0u8; lb];
    let mut com = vec![0u8; params.leaf_commitment_bytes()];
    leaf_commit(
        params,
        &tv.leaf_commit_key,
        &tv.leaf_commit_iv,
        tv.tweak,
        &tv.leaf_commit_uhash,
        &mut sd,
        &mut com,
    )
    .expect("valid call");
    assert_eq!(sd, tv.leaf_commit_expected_sd, "{name}: leaf seed");
    assert_eq!(com, tv.leaf_commit_expected_com, "{name}: leaf commitment");
}

#[test]
fn every_bavc_vector_is_reproduced() {
    let fixture = Fixture::load("bavc_tvs");
    let vectors = vectors(&fixture);
    assert_eq!(vectors.len(), 12);
    // Every entry has been read into `vectors`; nothing in the fixture is skipped.
    fixture.assert_consumed("");
    assert_eq!(
        fixture.names().len(),
        6 * 12 + 6 * 11,
        "twelve entries per AES set and eleven per Even-Mansour set"
    );
    for tv in &vectors {
        check_leaf_vector(tv);
    }
    in_parallel(&vectors, check_tree_vector);
    fixture.assert_consumed("");
}

/// The official hidden indices are in range for every set, and the challenge
/// decoder inverts this test's own bit packing of them.
///
/// This fixture holds no challenge bytes, so this test alone is not official
/// conformance of the decoder. The decoder's bit order and the grinding-bit
/// position are pinned by `tests/conformance_faest.rs`, which reproduces
/// `chall_3`, the opening and the counter of the official signatures of all
/// twelve sets.
#[test]
fn official_indices_are_decodable_challenges() {
    let fixture = Fixture::load("bavc_tvs");
    let vectors = vectors(&fixture);
    for tv in &vectors {
        let set = &tv.set;
        let params = set.vole();
        let hidden = tv.i_delta.clone();
        let mut challenge = vec![0u8; params.lambda().bytes()];
        let mut low = 0;
        for (vector, &index) in hidden.iter().enumerate() {
            let depth = params.depth(vector).expect("vector below tau");
            assert!(usize::from(index) < 1 << depth, "{}", set.name());
            for offset in 0..depth {
                let bit = u8::try_from((index >> offset) & 1).expect("one bit");
                challenge[(low + offset) / 8] |= bit << ((low + offset) % 8);
            }
            low += depth;
        }
        assert_eq!(low, params.n_delta());
        assert_eq!(decode_challenge(params, &challenge), Ok(hidden));
        // Any grinding bit makes the challenge undecodable.
        if params.w_grind() > 0 {
            *challenge.last_mut().expect("non-empty") |= 0x80;
            assert_eq!(
                decode_challenge(params, &challenge),
                Err(BavcError::GrindingBitsSet)
            );
        }
    }
    fixture.assert_consumed("");
}

/// Commit, open and reconstruct with inputs other than the official ones, on all
/// twelve standard rows and on two custom rows.
#[test]
fn commit_open_reconstruct_round_trips_on_every_row() {
    let rows = standard_and_custom_rows();
    in_parallel(&rows, |(name, params)| {
        let lb = params.lambda().bytes();
        let root: Vec<u8> = (0..lb)
            .map(|byte| u8::try_from(255 - 5 * byte).expect("small"))
            .collect();
        let commitment = commit(params, &root, &OTHER_IV).expect("valid call");
        let mut patterns = Patterns {
            state: u64::try_from(params.leaves()).expect("small"),
        };
        let hidden = patterns.find(params, true);
        let decommitment = commitment.open(&hidden).expect("pattern fits");
        let rebuilt = reconstruct(params, &decommitment, &hidden, &OTHER_IV).expect("valid");
        assert_eq!(rebuilt.commitment(), commitment.commitment(), "{name}");
        for (vector, &delta) in hidden.iter().enumerate() {
            let mut expected = commitment.seeds(vector).expect("below tau").to_vec();
            expected[usize::from(delta) * lb..(usize::from(delta) + 1) * lb].fill(0);
            assert_eq!(rebuilt.seeds(vector), Some(&expected[..]), "{name}");
        }
        // The commitment binds the iv.
        let other = reconstruct(params, &decommitment, &hidden, &ZERO_IV).expect("well formed");
        assert_ne!(other.commitment(), commitment.commitment(), "{name}");
    });
}

/// Every standard row has patterns that need more than `T_open` node keys: the
/// prover reports the typed retry outcome and the verifier rejects the pattern.
#[test]
fn patterns_above_t_open_are_a_typed_failure() {
    let rows = standard_and_custom_rows();
    for (name, params) in &rows {
        let mut patterns = Patterns { state: 0x5eed };
        let hidden = patterns.find(params, false);
        let nodes = opening_nodes(params, &hidden).expect("valid pattern");
        assert!(nodes > params.t_open(), "{name}");
        let expected = BavcError::OpeningTooLarge {
            nodes,
            t_open: params.t_open(),
        };
        assert!(expected.is_retry());
        assert_eq!(
            reconstruct(
                params,
                &vec![0u8; decommitment_bytes(params)],
                &hidden,
                &ZERO_IV
            ),
            Err(expected),
            "{name}"
        );
    }
    // The prover side, on the fast 128-bit rows and the custom rows.
    let fast: Vec<&(String, VoleParams)> = rows
        .iter()
        .filter(|(name, _)| name.ends_with("128f") || name.starts_with("custom"))
        .collect();
    assert_eq!(fast.len(), 4);
    in_parallel(&fast, |(name, params)| {
        let commitment = commit(params, &root_key(params), &ZERO_IV).expect("valid call");
        let mut patterns = Patterns { state: 0x5eed };
        let hidden = patterns.find(params, false);
        let nodes = opening_nodes(params, &hidden).expect("valid pattern");
        assert_eq!(
            commitment.open(&hidden),
            Err(BavcError::OpeningTooLarge {
                nodes,
                t_open: params.t_open()
            }),
            "{name}"
        );
        // The next pattern that fits opens: the retry loop of the signer.
        let hidden = patterns.find(params, true);
        assert!(commitment.open(&hidden).is_ok(), "{name}");
    });
}

/// A single flipped bit anywhere in a decommitment is rejected or changes the
/// reconstructed commitment.
#[test]
fn single_bit_flips_never_reconstruct_the_commitment() {
    let rows: Vec<(String, VoleParams)> = standard_and_custom_rows()
        .into_iter()
        .filter(|(name, _)| name.ends_with('f') || name.starts_with("custom"))
        .collect();
    assert_eq!(rows.len(), 8);
    in_parallel(&rows, |(name, params)| {
        let lb = params.lambda().bytes();
        let commitment = commit(params, &root_key(params), &OTHER_IV).expect("valid call");
        let mut patterns = Patterns { state: 77 };
        let hidden = patterns.find(params, true);
        let decommitment = commitment.open(&hidden).expect("pattern fits");
        let nodes = opening_nodes(params, &hidden).expect("valid pattern");
        let keys_at = params.tau() * params.leaf_commitment_bytes();
        let padding_at = keys_at + nodes * lb;
        assert!(padding_at < decommitment.len(), "{name}: has padding");

        // The first and last byte of each region and a spread of positions.
        let mut positions = vec![
            0,
            keys_at - 1,
            keys_at,
            padding_at - 1,
            padding_at,
            decommitment.len() - 1,
        ];
        positions.extend((0..decommitment.len()).step_by(decommitment.len() / 23 + 1));
        for position in positions {
            let mut tampered = decommitment.clone();
            tampered[position] ^= 1 << (position % 8);
            let outcome = reconstruct(params, &tampered, &hidden, &OTHER_IV);
            if position >= padding_at {
                assert_eq!(
                    outcome,
                    Err(BavcError::NonZeroPadding),
                    "{name}: {position}"
                );
            } else {
                let rebuilt = outcome.expect("well formed");
                assert_ne!(
                    rebuilt.commitment(),
                    commitment.commitment(),
                    "{name}: byte {position}"
                );
            }
        }

        // The intact decommitment under any other single-index change.
        for vector in [0, params.tau() / 2, params.tau() - 1] {
            let mut moved = hidden.clone();
            moved[vector] ^= 1;
            match reconstruct(params, &decommitment, &moved, &OTHER_IV) {
                Ok(rebuilt) => {
                    assert_ne!(rebuilt.commitment(), commitment.commitment(), "{name}");
                }
                Err(error) => assert!(
                    matches!(
                        error,
                        BavcError::NonZeroPadding | BavcError::OpeningTooLarge { .. }
                    ),
                    "{name}: {error}"
                ),
            }
        }
    });
}

/// Wrong lengths, wrong index counts and out-of-range indices are rejected with
/// the specific error on a standard row, before any tree work.
#[test]
fn malformed_inputs_are_rejected_with_the_specific_error() {
    for set in &FAEST_PARAMETER_SETS {
        let params = set.vole();
        let lb = params.lambda().bytes();
        let length = decommitment_bytes(params);
        let zeros = vec![0u8; length + lb];
        let hidden = vec![0u16; params.tau()];
        for wrong in [0, length - 1, length + 1, length - lb, length + lb] {
            assert_eq!(
                reconstruct(params, &zeros[..wrong], &hidden, &ZERO_IV),
                Err(BavcError::InvalidLength {
                    input: Input::Decommitment,
                    expected: length,
                    actual: wrong
                }),
                "{}",
                set.name()
            );
        }
        for wrong in [0, params.tau() - 1, params.tau() + 1] {
            let count = BavcError::InvalidIndexCount {
                expected: params.tau(),
                actual: wrong,
            };
            assert_eq!(
                reconstruct(params, &zeros[..length], &vec![0u16; wrong], &ZERO_IV),
                Err(count)
            );
            assert_eq!(opening_nodes(params, &vec![0u16; wrong]), Err(count));
        }
        for vector in [0, params.tau() - 1] {
            let leaves = params.leaves_of(vector).expect("vector below tau");
            let mut out_of_range = hidden.clone();
            out_of_range[vector] = u16::try_from(leaves).expect("fits");
            let expected = BavcError::IndexOutOfRange {
                vector,
                index: leaves,
                leaves,
            };
            assert_eq!(
                reconstruct(params, &zeros[..length], &out_of_range, &ZERO_IV),
                Err(expected),
                "{}",
                set.name()
            );
            assert_eq!(opening_nodes(params, &out_of_range), Err(expected));
            assert_eq!(position_in_tree(params, vector, leaves), None);
        }
        for wrong in [lb - 1, lb + 1] {
            assert_eq!(
                commit(params, &zeros[..wrong], &ZERO_IV).map(|_| ()),
                Err(BavcError::InvalidLength {
                    input: Input::RootSeed,
                    expected: lb,
                    actual: wrong
                })
            );
            assert_eq!(
                decode_challenge(params, &zeros[..wrong]),
                Err(BavcError::InvalidLength {
                    input: Input::Challenge,
                    expected: lb,
                    actual: wrong
                })
            );
        }
    }
}

/// `SHAKE(message || domain)` at the level's rate, squeezed to `out_bytes`.
fn shake(level: SecurityLevel, pieces: &[&[u8]], domain: u8, out_bytes: usize) -> Vec<u8> {
    let mut xof = Xof::new(level);
    for piece in pieces {
        xof.update(piece);
    }
    xof.update(&[domain]);
    let mut out = vec![0u8; out_bytes];
    xof.finalize().squeeze(&mut out);
    out
}

/// `BAVC.Commit` restated from Figures 5.2 to 5.4 on the bare sponge and generator,
/// with the domain bytes of `H_0` and `H_1` as parameters. It shares no code with
/// the `bavc` module or with the `Hasher` type.
fn commit_from_the_figures(
    params: &VoleParams,
    root: &[u8],
    iv: &[u8; 16],
    h0_domain: u8,
    h1_domain: u8,
) -> Vec<u8> {
    let level = params.lambda();
    let lb = level.bytes();
    let (tau, tau1, leaves) = (params.tau(), params.tau1(), params.leaves());
    let half = 1usize << (params.k() - 1);
    let tweak = |value: usize| u32::try_from(value).expect("small");

    let mut keys = vec![root.to_vec()];
    for node in 0..leaves - 1 {
        let mut children = vec![0u8; 2 * lb];
        prg(&keys[node], iv, tweak(node), 16 * lb, &mut children).expect("valid call");
        keys.push(children[..lb].to_vec());
        keys.push(children[lb..].to_vec());
    }
    let uhash = shake(level, &[iv], h0_domain, 3 * lb);

    let mut vector_hashes = Vec::new();
    for vector in 0..tau {
        let mut commitments = Vec::new();
        for index in 0..params.leaves_of(vector).expect("vector below tau") {
            let node = if index < half {
                leaves - 1 + tau * index + vector
            } else {
                leaves - 1 + tau * half + tau1 * (index % half) + vector
            };
            let twk = tweak(vector + leaves - 1);
            if params.n_leafcom() == 3 {
                let mut expanded = vec![0u8; 4 * lb];
                prg(&keys[node], iv, twk, 32 * lb, &mut expanded).expect("valid call");
                let mut com = vec![0u8; 3 * lb];
                match level {
                    SecurityLevel::L128 => leaf_hash_bytes::<Gf128>(&uhash, &expanded, &mut com),
                    SecurityLevel::L192 => leaf_hash_bytes::<Gf192>(&uhash, &expanded, &mut com),
                    SecurityLevel::L256 => leaf_hash_bytes::<Gf256>(&uhash, &expanded, &mut com),
                }
                .expect("exact lengths");
                commitments.extend(com);
            } else {
                let mut com = vec![0u8; 2 * lb];
                prg(&keys[node], iv, twk, 16 * lb, &mut com).expect("valid call");
                commitments.extend(com);
            }
        }
        vector_hashes.extend(shake(level, &[&commitments], h1_domain, 2 * lb));
    }
    shake(level, &[&vector_hashes], h1_domain, 2 * lb)
}

/// Settles two items stage 1 left unconfirmed by official vectors: the domain
/// bytes of `H_0` (`0x00`) and `H_1` (`0x01`), with outputs of `3 lambda` and
/// `2 lambda` bits from SHAKE128 (`lambda = 128`) or SHAKE256. The official `h`
/// is reproduced with exactly these values and with no neighbouring choice.
#[test]
fn the_vectors_pin_the_h0_and_h1_domain_bytes_and_lengths() {
    let fixture = Fixture::load("bavc_tvs");
    let fast: Vec<(FaestParams, Vec<u8>)> = vectors(&fixture)
        .into_iter()
        .filter(|tv| tv.set.name().ends_with('f'))
        .map(|tv| (tv.set, tv.h))
        .collect();
    assert_eq!(fast.len(), 6);
    in_parallel(&fast, |(set, h)| {
        let name = set.name();
        let params = set.vole();
        let root = root_key(params);
        let run = |h0, h1| commit_from_the_figures(params, &root, &ZERO_IV, h0, h1);

        // `h` is `2 lambda` bits and comes out with H_0 = 0x00 and H_1 = 0x01.
        assert_eq!(h.len(), 2 * params.lambda().bytes(), "{name}");
        assert_eq!(&run(0, 1), h, "{name}: specified domain bytes");
        // H_1 with any other domain byte fails.
        for h1 in [0, 2, 3, 4, 5, 8] {
            assert_ne!(&run(0, h1), h, "{name}: H_1 domain {h1}");
        }
        // H_0 with any other domain byte fails where the leaf hash uses it; the
        // Even-Mansour rows do not call H_0 at all.
        for h0 in [1, 2, 8] {
            match LeafScheme::of(params) {
                LeafScheme::Hashed => assert_ne!(&run(h0, 1), h, "{name}: H_0 domain {h0}"),
                LeafScheme::Direct => assert_eq!(&run(h0, 1), h, "{name}: H_0 unused"),
            }
        }
    });
    // The module under test agrees with the restatement away from the vectors.
    for params in [custom_row(3), custom_row(2)] {
        let root = root_key(&params);
        assert_eq!(
            commit(&params, &root, &OTHER_IV)
                .expect("valid call")
                .commitment(),
            commit_from_the_figures(&params, &root, &OTHER_IV, 0, 1)
        );
    }
    fixture.assert_consumed("");
}
