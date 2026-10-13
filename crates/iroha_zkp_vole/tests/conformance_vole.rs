//! VOLE conformance against the official FAEST v3.0.2 vectors (`vole_tvs`), which
//! the upstream `tests/vole.cpp` checks for all twelve parameter sets, and
//! black-box tests of `VOLECommit` and `VOLEReconstruct` on standard and custom
//! rows.
//!
//! Upstream inputs that are not in the fixture: `iv` is 16 zero bytes and the root
//! seed is the first `lambda / 8` bytes of `00 01 02 .. 1f`.
//!
//! The upstream generator (`tests/generate_vole_tv.cpp`) draws `chall` at random
//! and ignores the result of its challenge decoder, so every stored challenge has
//! non-zero grinding bits. Its `vole_reconstruct` reads only the low `n_Delta`
//! bits. The vector test therefore clears the grinding bits before calling the
//! strict [`reconstruct`], and a separate test shows that the stored challenges
//! are rejected as they are.

mod common;

use std::thread;

use common::{Fixture, hash_array};
use iroha_zkp_vole::{
    bavc::{self, BavcError},
    crt::{CrtTables, generator},
    field::{Gf128, Gf192, Gf256, LambdaField},
    hash::{Xof, h5},
    params::{
        FAEST_128F, FAEST_128S, FAEST_256F, FAEST_PARAMETER_SETS, FaestParams, ProofParams,
        SecurityLevel, VoleParams,
    },
    prg::Prg,
    vole::{
        Commitment, Input, MASK_TWEAK, Reconstruction, SMALL_VOLE_TWEAK, VoleError, commit,
        commit_with_tables, convert_to_vole, convert_to_vole_hidden, corrections_bytes, elements,
        mult_corrections_bytes, reconstruct, reconstruct_with_tables,
    },
};

const ZERO_IV: [u8; 16] = [0; 16];
/// Word 3 is `0xfffffffe`: every small-VOLE tweak and the mask tweak wrap.
const OTHER_IV: [u8; 16] = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xfe, 0xff, 0xff, 0xff,
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

fn bit(bytes: &[u8], position: usize) -> u8 {
    (bytes[position / 8] >> (position % 8)) & 1
}

fn words(bytes: &[u8], count: usize) -> Vec<u64> {
    let mut padded = bytes.to_vec();
    padded.resize(count * 8, 0);
    padded
        .chunks_exact(8)
        .map(|chunk| u64::from_le_bytes(chunk.try_into().expect("eight bytes")))
        .collect()
}

fn word_bytes(words: &[u64], len: usize) -> Vec<u8> {
    let mut bytes: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    bytes.truncate(len);
    bytes
}

/// `challenge` with its top `w_grind` bits cleared.
fn without_grinding_bits(params: &VoleParams, challenge: &[u8]) -> Vec<u8> {
    let mut cleared = challenge.to_vec();
    for position in params.n_delta()..params.lambda().bits() {
        cleared[position / 8] &= !(1 << (position % 8));
    }
    cleared
}

/// A deterministic sequence of challenges with zero grinding bits (64-bit LCG).
struct Challenges {
    state: u64,
}

impl Challenges {
    fn next(&mut self, params: &VoleParams) -> Vec<u8> {
        let raw: Vec<u8> = (0..params.lambda().bytes())
            .map(|_| {
                self.state = self
                    .state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                self.state.to_le_bytes()[7]
            })
            .collect();
        without_grinding_bits(params, &raw)
    }

    /// The first challenge whose pattern `commitment` can open, with its opening.
    fn openable(&mut self, commitment: &Commitment) -> (Vec<u8>, Vec<u8>) {
        let params = *commitment.params().vole();
        for _ in 0..4096 {
            let challenge = self.next(&params);
            let hidden = bavc::decode_challenge(&params, &challenge).expect("no grinding bits");
            match commitment.open(&hidden) {
                Ok(decommitment) => return (challenge, decommitment),
                Err(error) => assert!(error.is_retry(), "{error}"),
            }
        }
        panic!("no openable challenge found");
    }
}

/// `W_CRT * Delta'` computed as the upstream test does: `Delta'` assembled from the
/// hidden indices, instance `i` at its residue offset, then one inner product per
/// output bit.
fn delta_from_indices(params: &VoleParams, tables: &CrtTables<'_>, hidden: &[u16]) -> Vec<u8> {
    let mut selector = vec![0u8; params.n_delta().div_ceil(8)];
    let mut offset = 0;
    for (instance, &index) in hidden.iter().enumerate() {
        let depth = params.depth(instance).expect("instance below tau");
        for position in 0..depth {
            selector[(offset + position) / 8] |=
                u8::try_from((index >> position) & 1).expect("bit") << ((offset + position) % 8);
        }
        offset += depth;
    }
    assert_eq!(offset, params.n_delta());
    let selector = words(&selector, tables.w_crt().words_per_row());
    let mut delta = vec![0u8; params.lambda().bytes()];
    for row in 0..params.lambda().bits() {
        let set = tables.w_crt().row_dot(row, &selector).expect("shape");
        delta[row / 8] |= u8::from(set) << (row % 8);
    }
    delta
}

/// `Q[j] = V[j] + u[j] * Delta` for every row and `qbar_m = vbar_m + ubar_m * Delta`
/// for every mask, in `GF(2^lambda)`.
fn assert_relations_in<F: LambdaField>(name: &str, prover: &Commitment, verifier: &Reconstruction) {
    let vole = prover.params().vole();
    let delta = elements::<F>(vole, verifier.delta()).expect("one element")[0];
    let v = elements::<F>(vole, prover.v()).expect("elements");
    let q = elements::<F>(vole, verifier.q()).expect("elements");
    assert_eq!(v.len(), prover.params().witness_bits(), "{name}");
    assert_eq!(q.len(), v.len(), "{name}");
    for (row, (q, v)) in q.iter().zip(v.iter()).enumerate() {
        assert_eq!(
            *q,
            *v + delta.mul_bit(bit(prover.u(), row)),
            "{name}: row {row}"
        );
    }
    let u_masks = elements::<F>(vole, prover.u_masks()).expect("elements");
    let v_masks = elements::<F>(vole, prover.v_masks()).expect("elements");
    let q_masks = elements::<F>(vole, verifier.q_masks()).expect("elements");
    assert_eq!(u_masks.len(), vole.n_mask(), "{name}");
    assert_eq!(q_masks.len(), vole.n_mask(), "{name}");
    for mask in 0..vole.n_mask() {
        assert_eq!(
            q_masks[mask],
            v_masks[mask] + u_masks[mask] * delta,
            "{name}: mask {mask}"
        );
    }
}

fn assert_relations(name: &str, prover: &Commitment, verifier: &Reconstruction) {
    match prover.params().vole().lambda() {
        SecurityLevel::L128 => assert_relations_in::<Gf128>(name, prover, verifier),
        SecurityLevel::L192 => assert_relations_in::<Gf192>(name, prover, verifier),
        SecurityLevel::L256 => assert_relations_in::<Gf256>(name, prover, verifier),
    }
}

/// All entries of one fixture namespace.
struct Vector {
    set: FaestParams,
    h: Vec<u8>,
    hashed_c: Vec<u8>,
    hashed_u: Vec<u8>,
    hashed_c_mult: Vec<u8>,
    hashed_v: Vec<u8>,
    hashed_bar_u: Vec<u8>,
    hashed_bar_v: Vec<u8>,
    hashed_q: Vec<u8>,
    hashed_bar_q: Vec<u8>,
    chall: Vec<u8>,
}

fn vectors(fixture: &Fixture) -> Vec<Vector> {
    FAEST_PARAMETER_SETS
        .iter()
        .map(|set| {
            let name = |entry: &str| format!("vole_tvs.{}.{entry}", fixture_name(set));
            Vector {
                set: *set,
                h: fixture.bytes(&name("h")),
                hashed_c: fixture.bytes(&name("hashed_c")),
                hashed_u: fixture.bytes(&name("hashed_u")),
                hashed_c_mult: fixture.bytes(&name("hashed_c_mult")),
                hashed_v: fixture.bytes(&name("hashed_v")),
                hashed_bar_u: fixture.bytes(&name("hashed_barU")),
                hashed_bar_v: fixture.bytes(&name("hashed_barV")),
                hashed_q: fixture.bytes(&name("hashed_q")),
                hashed_bar_q: fixture.bytes(&name("hashed_barQ")),
                chall: fixture.bytes(&name("chall")),
            }
        })
        .collect()
}

/// The upstream `test_tv` on one parameter set: every published hash, the
/// reconstructed commitment and the bytewise `Q = V + u * Delta` loop.
fn check_vector(tv: &Vector) {
    let name = tv.set.name();
    let params = tv.set.proof();
    let vole = params.vole();
    let lb = vole.lambda().bytes();
    let ell = params.witness_bits();

    let prover = commit(params, &root_key(vole), &ZERO_IV).expect("commit");
    assert_eq!(prover.commitment(), tv.h, "{name}: h");
    assert_eq!(prover.corrections().len(), (vole.tau() - 1) * ell / 8);
    assert_eq!(
        hash_array(prover.corrections()).as_slice(),
        tv.hashed_c,
        "{name}: c"
    );
    assert_eq!(prover.u().len(), ell / 8);
    assert_eq!(hash_array(prover.u()).as_slice(), tv.hashed_u, "{name}: u");
    assert_eq!(prover.u_masks().len(), vole.n_mask() * lb);
    assert_eq!(
        hash_array(prover.u_masks()).as_slice(),
        tv.hashed_bar_u,
        "{name}: barU"
    );
    assert_eq!(
        hash_array(prover.v_masks()).as_slice(),
        tv.hashed_bar_v,
        "{name}: barV"
    );
    assert_eq!(
        prover.mult_corrections().len(),
        vole.n_mask() * vole.n_mult().div_ceil(8)
    );
    assert_eq!(
        hash_array(prover.mult_corrections()).as_slice(),
        tv.hashed_c_mult,
        "{name}: c_mult"
    );
    // Upstream repacks its row-major storage into `ell` elements of `lambda` bits.
    assert_eq!(prover.v().len(), ell * lb);
    assert_eq!(hash_array(prover.v()).as_slice(), tv.hashed_v, "{name}: V");

    // Upstream decodes the low `n_Delta` bits of the stored challenge and opens.
    assert_eq!(tv.chall.len(), lb, "{name}");
    let challenge = without_grinding_bits(vole, &tv.chall);
    let hidden = bavc::decode_challenge(vole, &challenge).expect("grinding bits cleared");
    let decommitment = prover.open(&hidden).expect("upstream opened this pattern");
    let verifier = reconstruct(
        params,
        &challenge,
        &decommitment,
        prover.corrections(),
        prover.mult_corrections(),
        &ZERO_IV,
    )
    .expect("reconstruct");
    assert_eq!(verifier.commitment(), tv.h, "{name}: reconstructed h");
    assert_eq!(verifier.hidden_indices(), hidden, "{name}");
    assert_eq!(verifier.q().len(), ell * lb);
    assert_eq!(
        hash_array(verifier.q()).as_slice(),
        tv.hashed_q,
        "{name}: Q"
    );
    assert_eq!(
        hash_array(verifier.q_masks()).as_slice(),
        tv.hashed_bar_q,
        "{name}: barQ"
    );

    // The closing loop of the upstream test, with its own `Delta`.
    let tables = vole.crt_tables().expect("embedded tables");
    let delta = delta_from_indices(vole, tables, &hidden);
    assert_eq!(verifier.delta(), delta, "{name}: Delta");
    for row in 0..ell {
        let mut expected = prover.v()[row * lb..(row + 1) * lb].to_vec();
        if bit(prover.u(), row) == 1 {
            for (slot, byte) in expected.iter_mut().zip(&delta) {
                *slot ^= *byte;
            }
        }
        assert_eq!(
            &verifier.q()[row * lb..(row + 1) * lb],
            expected,
            "{name}: row {row}"
        );
    }
    // Beyond upstream: the mask relation in the field.
    assert_relations(name, &prover, &verifier);
}

#[test]
fn every_vole_vector_is_reproduced() {
    let fixture = Fixture::load("vole_tvs");
    let vectors = vectors(&fixture);
    assert_eq!(vectors.len(), 12);
    // Every entry has been read into `vectors`; nothing in the fixture is skipped.
    fixture.assert_consumed("");
    assert_eq!(fixture.names().len(), 10 * 12, "ten entries per set");
    in_parallel(&vectors, check_vector);
    fixture.assert_consumed("");
}

/// The stored challenges are not valid third challenges: each has a grinding bit
/// set, so strict decoding and the strict verifier reject them. This is the
/// behaviour the vector test works around by clearing those bits.
#[test]
fn strict_decoding_rejects_the_stored_challenges() {
    let fixture = Fixture::load("vole_tvs");
    for tv in vectors(&fixture) {
        let name = tv.set.name();
        let params = tv.set.proof();
        let vole = params.vole();
        assert!(
            (vole.n_delta()..vole.lambda().bits()).any(|position| bit(&tv.chall, position) == 1),
            "{name}: a grinding bit is set"
        );
        assert_eq!(
            bavc::decode_challenge(vole, &tv.chall),
            Err(BavcError::GrindingBitsSet),
            "{name}"
        );
        // The verifier decodes before it touches the decommitment.
        let rejected = reconstruct(
            params,
            &tv.chall,
            &vec![0u8; bavc::decommitment_bytes(vole)],
            &vec![0u8; corrections_bytes(params)],
            &vec![0u8; mult_corrections_bytes(vole)],
            &ZERO_IV,
        )
        .expect_err("grinding bits set");
        assert_eq!(
            rejected,
            VoleError::Bavc(BavcError::GrindingBitsSet),
            "{name}"
        );
        assert!(rejected.is_retry());
    }
    fixture.assert_consumed("");
}

/// A row with the FAEST-128f tree and seven masks (`d_zk = 4`).
fn seven_mask_row() -> ProofParams {
    let vole = VoleParams::new(SecurityLevel::L128, 17, 8, 108, 3, 4, 312).expect("valid row");
    ProofParams::new(vole, 136, 200).expect("valid row")
}

/// A row that is none of the standard ones, with tables from the generator:
/// `lambda = 128`, `tau = 16`, `w_grind = 8`, eight trees of depth 8 and eight of
/// depth 7. `T_open` is large enough for every pattern.
fn generated_row() -> (ProofParams, CrtTables<'static>) {
    let tables = generator::generate(128, 16, 8).expect("supported parameters");
    let n_mult = usize::try_from(tables.n_mult()).expect("small");
    let vole = VoleParams::new(SecurityLevel::L128, 16, 8, 512, 2, 7, n_mult).expect("valid row");
    (ProofParams::new(vole, 160, 161).expect("valid row"), tables)
}

fn round_trip(name: &str, params: &ProofParams, tables: &CrtTables<'_>, iv: &[u8; 16]) {
    let vole = params.vole();
    let mut root = root_key(vole);
    root.reverse();
    let prover = commit_with_tables(params, tables, &root, iv).expect("commit");
    let mut challenges = Challenges { state: 0x5eed };
    for _ in 0..2 {
        let (challenge, decommitment) = challenges.openable(&prover);
        let verifier = reconstruct_with_tables(
            params,
            tables,
            &challenge,
            &decommitment,
            prover.corrections(),
            prover.mult_corrections(),
            iv,
        )
        .expect("reconstruct");
        assert_eq!(verifier.commitment(), prover.commitment(), "{name}");
        let hidden = bavc::decode_challenge(vole, &challenge).expect("valid challenge");
        assert_eq!(
            verifier.delta(),
            delta_from_indices(vole, tables, &hidden),
            "{name}"
        );
        // The top `w_grind` coefficients of `Delta` and of every `Q[j]` are zero.
        let lb = vole.lambda().bytes();
        for element in verifier.delta().chunks(lb).chain(verifier.q().chunks(lb)) {
            assert!(
                (vole.n_delta()..vole.lambda().bits()).all(|position| bit(element, position) == 0),
                "{name}"
            );
        }
        assert_relations(name, &prover, &verifier);
    }
}

#[test]
fn commit_open_reconstruct_is_consistent_on_every_standard_row() {
    in_parallel(&FAEST_PARAMETER_SETS, |set| {
        let tables = set.vole().crt_tables().expect("embedded tables");
        round_trip(set.name(), set.proof(), tables, &OTHER_IV);
    });
}

#[test]
fn commit_open_reconstruct_is_consistent_on_custom_rows() {
    // A custom witness length on a standard row, the shortest and an odd one.
    for ell in [128, 1000] {
        let params = ProofParams::new(*FAEST_128S.vole(), ell, ell + 3).expect("valid row");
        let tables = params.vole().crt_tables().expect("embedded tables");
        round_trip("FAEST-128s tree, custom ell", &params, tables, &OTHER_IV);
    }
    // Another number of masks.
    let params = seven_mask_row();
    assert_eq!(params.vole().n_mask(), 7);
    let tables = params.vole().crt_tables().expect("embedded tables");
    round_trip("seven masks", &params, tables, &OTHER_IV);
    let prover = commit(&params, &root_key(params.vole()), &ZERO_IV).expect("commit");
    assert_eq!(prover.u_masks().len(), 7 * 16);
    assert_eq!(prover.mult_corrections().len(), 7 * 39);
    // A tree shape with no embedded tables.
    let (params, tables) = generated_row();
    assert!(params.vole().crt_tables().is_err());
    round_trip("generated tables", &params, &tables, &OTHER_IV);
}

/// The witness length the custom relation needs, on the FAEST-256f row: the
/// buffers are linear in `ell` and the relations hold on all 36,000 rows.
#[test]
fn a_36000_bit_witness_commits_and_reconstructs() {
    let params = ProofParams::new(*FAEST_256F.vole(), 36_000, 40_000).expect("valid row");
    assert_eq!(params.ell_hat(), 36_080);
    assert!(!params.within_proven_hash_bounds());
    let tables = params.vole().crt_tables().expect("embedded tables");
    let prover = commit(&params, &root_key(params.vole()), &OTHER_IV).expect("commit");
    assert_eq!(prover.u().len(), 4500);
    assert_eq!(prover.v().len(), 36_000 * 32);
    assert_eq!(prover.corrections().len(), 32 * 4500);
    let (challenge, decommitment) = Challenges { state: 36_000 }.openable(&prover);
    let verifier = reconstruct_with_tables(
        &params,
        tables,
        &challenge,
        &decommitment,
        prover.corrections(),
        prover.mult_corrections(),
        &OTHER_IV,
    )
    .expect("reconstruct");
    assert_eq!(verifier.commitment(), prover.commitment());
    assert_eq!(verifier.q().len(), 36_000 * 32);
    assert_relations("36,000 witness bits", &prover, &verifier);
}

/// A flipped bit of a correction `c_i` moves exactly one `Q[j]`, by the image
/// under `W_CRT` of the bits of `Delta'` that belong to instance `i`, and, when
/// `j < lambda`, the gate labels and with them the mask keys. A flipped bit of
/// `c_mult` moves exactly one mask key, by column `e` of `W_gate` when
/// `<G[e], Delta'> = 1`. Either way the relation with the prover's values breaks,
/// and nothing else changes.
#[test]
fn tampered_corrections_move_exactly_the_keys_they_feed() {
    let rows: Vec<(String, ProofParams, CrtTables<'static>)> = [FAEST_128F, FAEST_256F]
        .iter()
        .map(|set| {
            let tables = set.vole().crt_tables().expect("embedded tables").clone();
            (set.name().to_owned(), *set.proof(), tables)
        })
        .chain([{
            let (params, tables) = generated_row();
            ("generated tables".to_owned(), params, tables)
        }])
        .collect();
    in_parallel(&rows, |(name, params, tables)| {
        let vole = params.vole();
        let (lb, ell_bytes) = (vole.lambda().bytes(), params.witness_bytes());
        let prover =
            commit_with_tables(params, tables, &root_key(vole), &OTHER_IV).expect("commit");
        let (challenge, decommitment) = Challenges { state: 7 }.openable(&prover);
        let run = |corrections: &[u8], mult: &[u8]| {
            reconstruct_with_tables(
                params,
                tables,
                &challenge,
                &decommitment,
                corrections,
                mult,
                &OTHER_IV,
            )
            .expect("well-formed inputs are not rejected at this layer")
        };
        let honest = run(prover.corrections(), prover.mult_corrections());
        let hidden = honest.hidden_indices().to_vec();

        let lambda = vole.lambda().bits();
        assert!(params.witness_bits() > lambda, "{name}: rows on both sides");
        let mut moved_rows = 0;
        for instance in [1, 2, vole.tau() / 2, vole.tau() - 1] {
            // The part of `Delta'` that instance `instance` contributes.
            let mut part = vec![0u16; vole.tau()];
            part[instance] = hidden[instance];
            let shift = delta_from_indices(vole, tables, &part);
            let moves = hidden[instance] != 0;
            assert_eq!(
                shift.iter().any(|&byte| byte != 0),
                moves,
                "{name}: W_CRT is injective"
            );
            // One row that feeds the gate labels and one that does not.
            let label_row = (instance * 53 + 5) % lambda;
            let plain_row = lambda + (instance * 53 + 5) % (params.witness_bits() - lambda);
            for row in [label_row, plain_row] {
                let mut corrections = prover.corrections().to_vec();
                corrections[(instance - 1) * ell_bytes + row / 8] ^= 1 << (row % 8);
                let tampered = run(&corrections, prover.mult_corrections());
                assert_eq!(tampered.commitment(), honest.commitment(), "{name}");
                assert_eq!(tampered.delta(), honest.delta(), "{name}");
                for (at, (got, was)) in tampered
                    .q()
                    .chunks(lb)
                    .zip(honest.q().chunks(lb))
                    .enumerate()
                {
                    let difference: Vec<u8> = got.iter().zip(was).map(|(a, b)| a ^ b).collect();
                    if at == row {
                        assert_eq!(difference, shift, "{name}: instance {instance}");
                    } else {
                        assert!(difference.iter().all(|&byte| byte == 0), "{name}: row {at}");
                    }
                }
                // Rows `[0, lambda)` also enter the gate labels, and through the
                // hash every mask key; later rows enter nothing else.
                if moves && row < lambda {
                    assert_ne!(tampered.q_masks(), honest.q_masks(), "{name}");
                } else {
                    assert_eq!(tampered.q_masks(), honest.q_masks(), "{name}");
                }
            }
            moved_rows += usize::from(moves);
        }
        assert!(moved_rows > 0, "{name}: some instance has a non-zero index");

        let selector = words(&challenge, tables.g().words_per_row());
        let gate_bytes = vole.n_mult().div_ceil(8);
        let (mut selected, mut unselected) = (0, 0);
        for step in 0..12 {
            let gate = (step * 97 + 1) % vole.n_mult();
            let mask = step % vole.n_mask();
            let gamma = tables.g().row_dot(gate, &selector).expect("shape");
            // Column `gate` of `W_gate`.
            let mut unit = vec![0u64; tables.w_gate().words_per_row()];
            unit[gate / 64] = 1 << (gate % 64);
            let mut column = vec![0u64; lb / 8];
            tables.w_gate().mul_vec(&mut column, &unit).expect("shape");
            let column = word_bytes(&column, lb);

            let mut mult = prover.mult_corrections().to_vec();
            mult[mask * gate_bytes + gate / 8] ^= 1 << (gate % 8);
            let tampered = run(prover.corrections(), &mult);
            assert_eq!(tampered.commitment(), honest.commitment(), "{name}");
            assert_eq!(tampered.q(), honest.q(), "{name}");
            for (at, (got, was)) in tampered
                .q_masks()
                .chunks(lb)
                .zip(honest.q_masks().chunks(lb))
                .enumerate()
            {
                let difference: Vec<u8> = got.iter().zip(was).map(|(a, b)| a ^ b).collect();
                if at == mask && gamma {
                    assert_eq!(difference, column, "{name}: gate {gate}");
                    assert!(column.iter().any(|&byte| byte != 0), "{name}: gate {gate}");
                } else {
                    assert!(
                        difference.iter().all(|&byte| byte == 0),
                        "{name}: mask {at}"
                    );
                }
            }
            if gamma {
                selected += 1;
            } else {
                unselected += 1;
            }
        }
        assert!(selected > 0 && unselected > 0, "{name}: both kinds of gate");
    });
}

#[test]
fn malformed_inputs_are_rejected_with_the_specific_error() {
    let params = *FAEST_128F.proof();
    let vole = params.vole();
    let prover = commit(&params, &root_key(vole), &OTHER_IV).expect("commit");
    let (challenge, decommitment) = Challenges { state: 3 }.openable(&prover);
    let (c, cm) = (prover.corrections(), prover.mult_corrections());
    let run = |challenge: &[u8], decommitment: &[u8], c: &[u8], cm: &[u8]| {
        reconstruct(&params, challenge, decommitment, c, cm, &OTHER_IV).err()
    };
    assert_eq!(run(&challenge, &decommitment, c, cm), None);

    for (wrong, input, expected) in [
        (&c[..c.len() - 1], Input::Corrections, c.len()),
        (&[][..], Input::Corrections, c.len()),
    ] {
        assert_eq!(
            run(&challenge, &decommitment, wrong, cm),
            Some(VoleError::InvalidLength {
                input,
                expected,
                actual: wrong.len()
            })
        );
    }
    let mut long = cm.to_vec();
    long.push(0);
    assert_eq!(
        run(&challenge, &decommitment, c, &long),
        Some(VoleError::InvalidLength {
            input: Input::MultCorrections,
            expected: cm.len(),
            actual: cm.len() + 1
        })
    );
    assert_eq!(
        run(&challenge[..15], &decommitment, c, cm),
        Some(VoleError::Bavc(BavcError::InvalidLength {
            input: bavc::Input::Challenge,
            expected: 16,
            actual: 15
        }))
    );
    assert_eq!(
        run(&challenge, &decommitment[1..], c, cm),
        Some(VoleError::Bavc(BavcError::InvalidLength {
            input: bavc::Input::Decommitment,
            expected: decommitment.len(),
            actual: decommitment.len() - 1
        }))
    );
    for position in vole.n_delta()..vole.lambda().bits() {
        let mut ground = challenge.clone();
        ground[position / 8] |= 1 << (position % 8);
        let error = run(&ground, &decommitment, c, cm).expect("grinding bit set");
        assert_eq!(error, VoleError::Bavc(BavcError::GrindingBitsSet));
        assert!(error.is_retry());
    }
    // A decommitment for another pattern does not reproduce the commitment.
    let mut other = challenge.clone();
    other[0] ^= 1;
    if let Ok(opened) = reconstruct(&params, &other, &decommitment, c, cm, &OTHER_IV) {
        assert_ne!(opened.commitment(), prover.commitment());
    }
    assert_eq!(
        commit(&params, &root_key(vole)[1..], &OTHER_IV).err(),
        Some(VoleError::Bavc(BavcError::InvalidLength {
            input: bavc::Input::RootSeed,
            expected: 16,
            actual: 15
        }))
    );
    // Tables of another row.
    let foreign = FAEST_128S.vole().crt_tables().expect("embedded tables");
    assert_eq!(
        commit_with_tables(&params, foreign, &root_key(vole), &OTHER_IV).err(),
        Some(VoleError::TableMismatch {
            what: "tau",
            expected: 17,
            actual: 11
        })
    );

    // No row at hand has padding bits in `c_mult`: `n_mult` is a multiple of 8 on
    // the twelve standard rows and on the generated one. The rejection of a set
    // padding bit is covered by a unit test of the library.
    let (generated, _) = generated_row();
    for vole in FAEST_PARAMETER_SETS
        .iter()
        .map(FaestParams::vole)
        .chain([generated.vole()])
    {
        assert_eq!(vole.n_mult_padded(), vole.n_mult());
        assert_eq!(
            mult_corrections_bytes(vole) * 8,
            vole.n_mask() * vole.n_mult()
        );
    }
}

/// The upstream `test_convert_to_vole`: for random seeds and a random hidden
/// index, the verifier's columns plus `u` on the set bits of the index are the
/// prover's columns.
#[test]
fn convert_to_vole_matches_between_prover_and_verifier_on_every_row() {
    in_parallel(&FAEST_PARAMETER_SETS, |set| {
        let name = set.name();
        let vole = set.vole();
        let lb = vole.lambda().bytes();
        let bits = set.proof().ell_hat();
        let width = bits.div_ceil(8);
        let mut state = 0x0123_4567_89ab_cdef_u64;
        let mut next = move || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            state >> 33
        };
        for instance in 0..vole.tau() {
            let depth = vole.depth(instance).expect("instance below tau");
            let leaves = vole.leaves_of(instance).expect("instance below tau");
            let seeds: Vec<u8> = (0..leaves * lb).map(|_| next().to_le_bytes()[0]).collect();
            let index = usize::try_from(next()).expect("small") % leaves;
            let mut u = vec![0u8; width];
            let mut v = vec![0u8; depth * width];
            convert_to_vole(vole, instance, &OTHER_IV, &seeds, bits, &mut u, &mut v)
                .expect("valid call");
            let mut q = vec![0u8; depth * width];
            convert_to_vole_hidden(
                vole,
                instance,
                &OTHER_IV,
                &seeds,
                u16::try_from(index).expect("index fits"),
                bits,
                &mut q,
            )
            .expect("valid call");
            for (level, column) in q.chunks_mut(width).enumerate() {
                if (index >> level) & 1 == 1 {
                    for (slot, byte) in column.iter_mut().zip(&u) {
                        *slot ^= *byte;
                    }
                }
            }
            assert_eq!(q, v, "{name}: instance {instance}");
        }
    });
}

/// How the restatement below reads the two primitives stage 1 left unconfirmed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum H5Bits {
    /// Two squeezed bytes as a little-endian integer, mask `m` at bit `m`: the
    /// library's `h5`.
    Library,
    /// Mask `m` at bit `7 - m % 8` of squeezed byte `m / 8`.
    MostSignificantFirst,
    /// Two squeezed bytes as a big-endian integer, mask `m` at bit `m`.
    BigEndian,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Truncation {
    /// The first `bits` bits of the generator output: the low bits of the last
    /// byte are kept (`Prg::fill_bits`).
    LowBits,
    /// The high bits of the last byte are kept: the output read from bit
    /// `8 - bits % 8`.
    HighBits,
}

/// The quantities of one row that the restatement needs, computed once.
struct Restated {
    set: FaestParams,
    root: Vec<u8>,
    /// `u = u_0[0, ell)`.
    u: Vec<u8>,
    /// `u_low^(m)` as `n_Delta` bits.
    low: Vec<Vec<u8>>,
    /// Column `j` restricted to rows `[0, lambda)`.
    heads: Vec<Vec<u8>>,
}

impl Restated {
    /// Steps 1 to 3 of `VOLECommit` on the public building blocks.
    fn new(set: &FaestParams) -> Self {
        let params = set.proof();
        let vole = params.vole();
        let lb = vole.lambda().bytes();
        let (ell, bits) = (params.witness_bits(), params.ell_hat());
        let width = bits.div_ceil(8);
        let root = root_key(vole);
        let tree = bavc::commit(vole, &root, &ZERO_IV).expect("commit");
        let mut u = Vec::new();
        let mut low = vec![vec![0u8; vole.n_delta().div_ceil(8)]; vole.n_mask()];
        let mut heads = Vec::new();
        let mut start = 0;
        for instance in 0..vole.tau() {
            let depth = vole.depth(instance).expect("instance below tau");
            let mut instance_u = vec![0u8; width];
            let mut columns = vec![0u8; depth * width];
            convert_to_vole(
                vole,
                instance,
                &ZERO_IV,
                tree.seeds(instance).expect("instance below tau"),
                bits,
                &mut instance_u,
                &mut columns,
            )
            .expect("valid call");
            if instance == 0 {
                u = instance_u[..ell / 8].to_vec();
            }
            for (mask, low) in low.iter_mut().enumerate() {
                for position in 0..depth {
                    let row = ell + mask * vole.d0() + position;
                    low[(start + position) / 8] |=
                        bit(&instance_u, row) << ((start + position) % 8);
                }
            }
            heads.extend(columns.chunks(width).map(|column| column[..lb].to_vec()));
            start += depth;
        }
        Self {
            set: *set,
            root,
            u,
            low,
            heads,
        }
    }

    /// `ubar_0 || ... || ubar_{n_mask - 1}` with the given reading of the mask
    /// generator's output.
    fn mask_values(&self, truncation: Truncation) -> Vec<u8> {
        let vole = self.set.vole();
        let tables = vole.crt_tables().expect("embedded tables");
        let (lb, w) = (vole.lambda().bytes(), vole.w_grind());
        let bits = vole.n_mask() * w;
        let generator = Prg::new(&self.root).expect("seed");
        let mut high = vec![0u8; bits.div_ceil(8)];
        let skip = match truncation {
            Truncation::LowBits => {
                generator
                    .fill_bits(&ZERO_IV, MASK_TWEAK, bits, &mut high)
                    .expect("valid call");
                0
            }
            Truncation::HighBits => {
                generator
                    .fill(&ZERO_IV, MASK_TWEAK, &mut high)
                    .expect("valid call");
                (8 - bits % 8) % 8
            }
        };
        let mut out = Vec::new();
        for (mask, low) in self.low.iter().enumerate() {
            let mut value = vec![0u64; lb / 8];
            tables
                .w_crt()
                .mul_vec(&mut value, &words(low, tables.w_crt().words_per_row()))
                .expect("shape");
            let mut value = word_bytes(&value, lb);
            // `M_tree(x) * u_hi(x)`, bit by bit.
            let m_tree = word_bytes(tables.m_tree(), (vole.n_delta() + 1).div_ceil(8));
            for position in 0..w {
                let at = skip + mask * w + position;
                if at < 8 * high.len() && bit(&high, at) == 1 {
                    for coefficient in 0..=vole.n_delta() {
                        let target = coefficient + position;
                        value[target / 8] ^= bit(&m_tree, coefficient) << (target % 8);
                    }
                }
            }
            out.extend(value);
        }
        out
    }

    /// `c_mult` from mask values `u_masks`, with the given reading of `H_5`.
    fn mult_corrections(&self, u_masks: &[u8], order: H5Bits) -> Vec<u8> {
        let vole = self.set.vole();
        let tables = vole.crt_tables().expect("embedded tables");
        let level = vole.lambda();
        let (lb, n_mask, n_mult) = (level.bytes(), vole.n_mask(), vole.n_mult());
        let hash = |gate: u32, label: &[u8]| -> Vec<u8> {
            if order == H5Bits::Library {
                let value = h5(level, &ZERO_IV, gate, label, n_mask).expect("valid call");
                return (0..n_mask)
                    .map(|mask| u8::try_from((value >> mask) & 1).expect("bit"))
                    .collect();
            }
            let mut xof = Xof::new(level);
            xof.update(&ZERO_IV);
            xof.update(&gate.to_le_bytes());
            xof.update(label);
            xof.update(&[5]);
            let mut squeezed = [0u8; 2];
            xof.finalize().squeeze(&mut squeezed);
            (0..n_mask)
                .map(|mask| match order {
                    H5Bits::MostSignificantFirst => (squeezed[mask / 8] >> (7 - mask % 8)) & 1,
                    H5Bits::BigEndian | H5Bits::Library => {
                        u8::try_from((u16::from_be_bytes(squeezed) >> mask) & 1).expect("bit")
                    }
                })
                .collect()
        };
        let gate_bytes = n_mult.div_ceil(8);
        let mut out = vec![0u8; n_mask * gate_bytes];
        for gate in 0..n_mult {
            let mut label = vec![0u8; lb];
            for (column, head) in self.heads.iter().enumerate() {
                if tables.g().bit(gate, column) == Some(true) {
                    for (slot, byte) in label.iter_mut().zip(head) {
                        *slot ^= *byte;
                    }
                }
            }
            let other: Vec<u8> = label.iter().zip(&self.u).map(|(a, b)| a ^ b).collect();
            let number = u32::try_from(gate).expect("small");
            let (h0, h1) = (hash(number, &label), hash(number, &other));
            for mask in 0..n_mask {
                let value = words(&u_masks[mask * lb..(mask + 1) * lb], lb / 8);
                let dot = u8::from(tables.f().row_dot(gate, &value).expect("shape"));
                out[mask * gate_bytes + gate / 8] |= (h0[mask] ^ h1[mask] ^ dot) << (gate % 8);
            }
        }
        out
    }
}

/// Settles two items stage 1 left unconfirmed by official vectors.
///
/// * `H_5` output order at ten bits: the two squeezed bytes are a little-endian
///   integer and mask `m` takes bit `m`. The official `hashed_c_mult` is
///   reproduced with this reading and with neither alternative.
/// * Generator output of a length that is not a multiple of 8: the first bits are
///   kept, that is the low bits of the last byte. FAEST-128s draws
///   `n_mask * w_grind = 70` bits for the masks, and the official `hashed_barU` is
///   reproduced only with this reading. (Its small-VOLE strings are 1070 bits, but
///   no bit at or above `ell_hat` is ever read, so those cannot tell.)
///
/// The restatement shares the tables, the generator and `ConvertToVOLE` with the
/// library but none of the CRT layer of `VOLECommit`.
#[test]
fn the_vectors_pin_the_h5_bit_order_and_the_generator_truncation() {
    let fixture = Fixture::load("vole_tvs");
    let sets: Vec<(FaestParams, Vec<u8>, Vec<u8>)> = [FAEST_128S, FAEST_128F]
        .into_iter()
        .map(|set| {
            let entry = |entry: &str| format!("vole_tvs.{}.{entry}", fixture_name(&set));
            (
                set,
                fixture.bytes(&entry("hashed_barU")),
                fixture.bytes(&entry("hashed_c_mult")),
            )
        })
        .collect();
    in_parallel(&sets, |(set, official_bar_u, official_c_mult)| {
        let name = set.name();
        let vole = set.vole();
        let restated = Restated::new(set);

        let u_masks = restated.mask_values(Truncation::LowBits);
        assert_eq!(&hash_array(&u_masks), official_bar_u.as_slice(), "{name}");
        let whole_bytes = (vole.n_mask() * vole.w_grind()).is_multiple_of(8);
        let shifted = restated.mask_values(Truncation::HighBits);
        if whole_bytes {
            // FAEST-128f draws 80 bits: there is nothing to truncate.
            assert_eq!(shifted, u_masks, "{name}");
        } else {
            assert_eq!(vole.n_mask() * vole.w_grind(), 70, "{name}");
            assert_eq!(set.proof().ell_hat(), 1070, "{name}");
            assert_ne!(&hash_array(&shifted), official_bar_u.as_slice(), "{name}");
        }

        assert_eq!(vole.n_mask(), 10, "{name}");
        let c_mult = restated.mult_corrections(&u_masks, H5Bits::Library);
        assert_eq!(&hash_array(&c_mult), official_c_mult.as_slice(), "{name}");
        for order in [H5Bits::MostSignificantFirst, H5Bits::BigEndian] {
            let other = restated.mult_corrections(&u_masks, order);
            assert_ne!(
                &hash_array(&other),
                official_c_mult.as_slice(),
                "{name}: {order:?}"
            );
        }
        // The library computes the same bytes.
        let prover = commit(set.proof(), &restated.root, &ZERO_IV).expect("commit");
        assert_eq!(prover.u_masks(), u_masks, "{name}");
        assert_eq!(prover.mult_corrections(), c_mult, "{name}");
    });
    assert_eq!(SMALL_VOLE_TWEAK, 1 << 31);
    assert_eq!(MASK_TWEAK, (1 << 31) - 1);
}
