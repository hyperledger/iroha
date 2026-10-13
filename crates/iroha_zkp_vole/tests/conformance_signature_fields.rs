//! The relation-independent fields of the official FAEST v3.0.2 signatures,
//! reproduced with the generic engine's building blocks on all twelve sets.
//!
//! From the fixture's secret key, public key, message, signing randomness and
//! extended witness, and without the AES or EM relation, the prover's side
//! reproduces `iv_pre` (`H_2^0` and `H_3`), the corrections `c_1 .. c_{tau-1}` and
//! `c_mult` (`H_4` and `VOLECommit`), `u~` (`chall_1` and `VOLEHash`) and the masked
//! witness `d`, at the offsets of the proof codec. On the verifier's side the
//! strict decoder accepts the official signature, `VOLEReconstruct` of its opening
//! returns the prover's commitment, and `D = Q~ + Delta * u~` is the prover's `V~`.
//! The remaining fields (`a~_1 ..`, `chall_3`, the counter) depend on the relation.

mod common;

use common::Fixture;
use iroha_zkp_vole::{
    codec::{self, Field},
    field::{Gf128, Gf192, Gf256, LambdaField},
    hash::Namespace,
    params::{FAEST_PARAMETER_SETS, FaestParams, SecurityLevel},
    randomness::Tape,
    transcript::{challenge_1, derive_iv, message_digest},
    universal_hash::VoleHasher,
    vole::{self, Opening},
};

const SET_NAMES: [&str; 12] = [
    "faest_128s",
    "faest_128f",
    "faest_192s",
    "faest_192f",
    "faest_256s",
    "faest_256f",
    "faest_em_128s",
    "faest_em_128f",
    "faest_em_192s",
    "faest_em_192f",
    "faest_em_256s",
    "faest_em_256f",
];

/// `VOLEHash(chall_1, (rows, masks[..6]), masks[6..])`.
fn vole_hash<F: LambdaField>(
    challenge: &[u8],
    rows: impl Iterator<Item = F>,
    masks: &[F],
) -> Vec<u8> {
    let mut hasher = VoleHasher::<F>::new(challenge).expect("chall_1 length");
    for element in rows.chain(masks[..6].iter().copied()) {
        hasher.update(element);
    }
    let tail: [F; 4] = masks[6..].try_into().expect("ten masks");
    hasher
        .finalize(&tail)
        .iter()
        .flat_map(|element| element.to_bytes().as_ref().to_vec())
        .collect()
}

fn check<F: LambdaField>(fixture: &Fixture, set: &FaestParams, name: &str) {
    let entry = |field: &str| fixture.bytes(&format!("faest_tvs.{name}.{field}"));
    let (sk, pk, witness, signature) = (
        entry("sk"),
        entry("pk"),
        entry("witness"),
        entry("signature"),
    );
    let message = fixture.bytes("faest_tvs.message");
    let rho = fixture.bytes("faest_tvs.random_seed");
    let params = set.proof();
    let row = params.vole();
    let level = row.lambda();
    let lb = level.bytes();
    let reference = Namespace::REFERENCE;
    let field = |field: Field| {
        let offset = field.offset(params);
        &signature[offset..offset + field.bytes(params)]
    };

    // mu = H_2^0(pk || msg); (r, iv_pre) = H_3(k || mu || rho) with k the last
    // lambda / 8 bytes of sk and rho exactly the 16 fixture bytes.
    let mu = message_digest(reference, level, &[&pk, &message]).expect("valid call");
    let tape = Tape::derive(reference, level, &sk[sk.len() - lb..], &mu, &rho).expect("valid call");
    assert_eq!(tape.iv_pre(), field(Field::IvPre), "{name}: iv_pre");

    let iv = derive_iv(reference, level, tape.iv_pre(), &mu).expect("valid call");
    let commitment = vole::commit(params, tape.root(), &iv).expect("embedded tables");
    assert_eq!(
        commitment.corrections(),
        field(Field::Corrections),
        "{name}: c_i"
    );
    assert_eq!(
        commitment.mult_corrections(),
        field(Field::MultCorrections),
        "{name}: c_mult"
    );

    let first = challenge_1(
        reference,
        params,
        &mu,
        commitment.commitment(),
        commitment.corrections(),
        commitment.mult_corrections(),
        tape.iv_pre(),
    )
    .expect("valid call");
    let u = commitment.u();
    let u_masks = vole::elements::<F>(row, commitment.u_masks()).expect("row field");
    let u_tilde = vole_hash::<F>(
        &first,
        (0..params.witness_bits()).map(|bit| F::from_bit(u[bit / 8] >> (bit % 8))),
        &u_masks,
    );
    assert_eq!(u_tilde, field(Field::UTilde), "{name}: u~");
    let masked: Vec<u8> = witness.iter().zip(u).map(|(w, u)| w ^ u).collect();
    assert_eq!(masked, field(Field::MaskedWitness), "{name}: d");

    // The verifier's side of the same values, from the official bytes alone.
    let fields = codec::decode(params, &signature).expect("the official signature is canonical");
    assert_eq!(
        codec::encode(params, &fields).expect("valid fields"),
        signature
    );
    let opened = vole::reconstruct_in(
        reference,
        params,
        row.crt_tables().expect("embedded tables"),
        &Opening {
            challenge: fields.challenge,
            decommitment: fields.decommitment,
            corrections: fields.corrections,
            mult_corrections: fields.mult_corrections,
        },
        &derive_iv(reference, level, fields.iv_pre, &mu).expect("valid call"),
    )
    .expect("the official opening is accepted");
    assert_eq!(opened.commitment(), commitment.commitment(), "{name}: com");

    let v = vole::elements::<F>(row, commitment.v()).expect("row field");
    let v_masks = vole::elements::<F>(row, commitment.v_masks()).expect("row field");
    let v_tilde = vole_hash::<F>(&first, v.iter().copied(), &v_masks);
    let q = vole::elements::<F>(row, opened.q()).expect("row field");
    let q_masks = vole::elements::<F>(row, opened.q_masks()).expect("row field");
    let q_tilde = vole_hash::<F>(&first, q.iter().copied(), &q_masks);
    let delta = F::from_bytes(opened.delta()).expect("one element");
    let d_tilde: Vec<u8> = q_tilde
        .chunks_exact(lb)
        .zip(fields.u_tilde.chunks_exact(lb))
        .flat_map(|(q, u)| {
            let sum =
                F::from_bytes(q).expect("element") + delta * F::from_bytes(u).expect("element");
            sum.to_bytes().as_ref().to_vec()
        })
        .collect();
    assert_eq!(d_tilde, v_tilde, "{name}: D = V~");
}

#[test]
fn the_relation_independent_signature_fields_match_the_official_vectors() {
    let fixture = Fixture::load("faest_tvs");
    for (set, name) in FAEST_PARAMETER_SETS.iter().zip(SET_NAMES) {
        match set.vole().lambda() {
            SecurityLevel::L128 => check::<Gf128>(&fixture, set, name),
            SecurityLevel::L192 => check::<Gf192>(&fixture, set, name),
            SecurityLevel::L256 => check::<Gf256>(&fixture, set, name),
        }
    }
    fixture.assert_consumed("faest_tvs.");
}
