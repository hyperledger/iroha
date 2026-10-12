//! The generic proof engine on a toy relation: honest proofs, the cross-check
//! against the validated Python prototype, soundness and malleability rejections,
//! determinism, and the digests of the CRT tables the ballot descriptor binds.
//!
//! The FAEST relation itself is not involved: the relation here has constraints of
//! degree 1, 2, 4 and 7, an identically zero constraint, a constraint whose terms
//! have different degrees, and public-input-dependent linear terms with field
//! scalars.

use iroha_zkp_vole::{
    bavc,
    codec::{self, CodecError, Field},
    crt::codec::encode_words,
    field::{BinaryField, Gf128, Gf256, LambdaField},
    hash::Namespace,
    params::{FAEST_128F, FAEST_256F, FAEST_256S, FAEST_EM_128F, SecurityLevel, VoleParams},
    proof::{ProofContext, ProofError, prove, prove_without_witness_check, verify},
    quicksilver::{
        ConstraintSystem, Relation, is_satisfied, total_constraints, violated_constraints,
    },
    randomness::Tape,
    transcript::message_digest,
};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

/// Witness bits of [`Toy`].
const ELL: usize = 320;
/// The generator of the public scalars of constraint group F.
const SCALAR_SEED: u64 = 0x9e37_79b9_7f4a_7c15;

/// The toy relation. With `p_i` bit `i` of the public input (low bit first):
///
/// * A, `i < 8`, degree 1: `w[b] + w[b+1] + w[b+2] + p_i`, `b = 128 + 3i`;
/// * B, `i < 8`, degree 2: `w[b] w[b+1] + w[b+2] + p_{8+i}`, `b = 160 + 3i`;
/// * C, `i < 8`, degree 4: `w[b] w[b+1] w[b+2] w[b+3] + w[b+4] + p_{16+i}`,
///   `b = 192 + 5i`;
/// * D, `i < 4`, degree 7: `w[b] ... w[b+6] + w[b+7] + p_{24+i}`, `b = 232 + 8i`;
/// * E, identically zero: `w[264] * 0`;
/// * F, degree 1 with field scalars: `sum_{j<16} s_j w[272+j] + sum_j p_{32+j} s_j`
///   with `s_j = SCALAR_SEED^(j+1)`;
/// * G, mixed degrees: `w[288] w[289] + w[290] w[291] w[292] w[293] + w[294] + p_48`.
///
/// Witness bits `[0, 128)` and the remaining ones are free.
struct Toy;

fn public_bit(public: &[u8], index: usize) -> bool {
    public
        .get(index / 8)
        .is_some_and(|byte| (byte >> (index % 8)) & 1 == 1)
}

fn scalars<F: LambdaField>() -> [F; 16] {
    let seed = F::from_u64(SCALAR_SEED);
    let mut current = F::ONE;
    core::array::from_fn(|_| {
        current *= seed;
        current
    })
}

impl<F: LambdaField> Relation<F> for Toy {
    type PublicInput = [u8];

    fn witness_bits(&self) -> usize {
        ELL
    }

    fn constraints(&self) -> usize {
        31
    }

    fn emit<C: ConstraintSystem<Field = F>>(&self, public: &[u8], cs: &mut C) {
        let w = |index: usize| cs.witness(index);
        let mut out = Vec::with_capacity(31);
        for i in 0..8 {
            let b = 128 + 3 * i;
            let sum = cs.add(cs.add(w(b), w(b + 1)), w(b + 2));
            out.push(cs.add_bit(sum, public_bit(public, i)));
        }
        for i in 0..8 {
            let b = 160 + 3 * i;
            let sum = cs.add(cs.mul(w(b), w(b + 1)), w(b + 2));
            out.push(cs.add_bit(sum, public_bit(public, 8 + i)));
        }
        for i in 0..8 {
            let b = 192 + 5 * i;
            let product = cs.mul(cs.mul(w(b), w(b + 1)), cs.mul(w(b + 2), w(b + 3)));
            out.push(cs.add_bit(cs.add(product, w(b + 4)), public_bit(public, 16 + i)));
        }
        for i in 0..4 {
            let b = 232 + 8 * i;
            let mut product = w(b);
            for j in 1..7 {
                product = cs.mul(product, w(b + j));
            }
            out.push(cs.add_bit(cs.add(product, w(b + 7)), public_bit(public, 24 + i)));
        }
        out.push(cs.mul(w(264), cs.zero()));
        let scalars = scalars::<F>();
        let mut target = F::ZERO;
        let mut sum = cs.zero();
        for (j, scalar) in scalars.into_iter().enumerate() {
            target += scalar.mul_bit(u8::from(public_bit(public, 32 + j)));
            sum = cs.add(sum, cs.scale(w(272 + j), scalar));
        }
        out.push(cs.add(sum, cs.constant(target)));
        let low = cs.mul(w(288), w(289));
        let high = cs.mul(cs.mul(w(290), w(291)), cs.mul(w(292), w(293)));
        out.push(cs.add_bit(cs.add(cs.add(low, high), w(294)), public_bit(public, 48)));
        for value in out {
            cs.constrain(value);
        }
    }
}

/// The public input of the cross-check with the prototype.
const PUBLIC: [u8; 7] = [0xa5, 0x3c, 0x96, 0xe1, 0x0f, 0x72, 0x81];

fn hex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|at| u8::from_str_radix(&text[2 * at..2 * at + 2], 16).expect("hex digits"))
        .collect()
}

/// A witness of [`Toy`] for `public`: pseudorandom bits with the output bit of
/// every constraint set, and all seven factors of the even degree-7 constraints
/// set so that those products are one.
fn witness(public: &[u8], seed: u8) -> Vec<u8> {
    let mut bytes = vec![0u8; ELL / 8];
    let mut sponge = Shake256::default();
    sponge.update(b"proof_generic witness");
    sponge.update(&[seed]);
    sponge.finalize_xof().read(&mut bytes);
    let get = |bytes: &[u8], index: usize| (bytes[index / 8] >> (index % 8)) & 1 == 1;
    let set = |bytes: &mut [u8], index: usize, bit: bool| {
        bytes[index / 8] &= !(1 << (index % 8));
        bytes[index / 8] |= u8::from(bit) << (index % 8);
    };
    let p = |index: usize| public_bit(public, index);
    for i in 0..8 {
        let b = 128 + 3 * i;
        let bit = get(&bytes, b) ^ get(&bytes, b + 1) ^ p(i);
        set(&mut bytes, b + 2, bit);
        let b = 160 + 3 * i;
        let bit = (get(&bytes, b) & get(&bytes, b + 1)) ^ p(8 + i);
        set(&mut bytes, b + 2, bit);
        let b = 192 + 5 * i;
        let bit = (b..b + 4).all(|index| get(&bytes, index)) ^ p(16 + i);
        set(&mut bytes, b + 4, bit);
    }
    for i in 0..4 {
        let b = 232 + 8 * i;
        if i % 2 == 0 {
            (b..b + 7).for_each(|index| set(&mut bytes, index, true));
        }
        let bit = (b..b + 7).all(|index| get(&bytes, index)) ^ p(24 + i);
        set(&mut bytes, b + 7, bit);
    }
    for j in 0..16 {
        set(&mut bytes, 272 + j, p(32 + j));
    }
    let bit = (get(&bytes, 288) & get(&bytes, 289))
        ^ (290..294).all(|index| get(&bytes, index))
        ^ p(48);
    set(&mut bytes, 294, bit);
    bytes
}

fn pattern(len: usize, step: u8, offset: u8) -> Vec<u8> {
    (0..len)
        .map(|at| {
            u8::try_from(at % 256)
                .expect("below 256")
                .wrapping_mul(step)
                .wrapping_add(offset)
        })
        .collect()
}

fn tape(level: SecurityLevel, salt: u8) -> Tape {
    let iv_pre: [u8; 16] = pattern(16, 13, 5u8.wrapping_add(salt))
        .try_into()
        .expect("16 bytes");
    Tape::explicit(
        level,
        &pattern(level.bytes(), 11, 3u8.wrapping_add(salt)),
        &iv_pre,
    )
    .expect("valid tape")
}

fn shake256(data: &[u8], len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let mut sponge = Shake256::default();
    sponge.update(data);
    sponge.finalize_xof().read(&mut out);
    out
}

/// The 77-byte prefix shape of the ballot profile: 13 ASCII bytes and a 64-byte
/// digest.
fn ballot_like_prefix(role: &[u8]) -> Vec<u8> {
    let mut prefix = b"PARL/FAEST/v1".to_vec();
    prefix.extend(shake256(role, 64));
    assert_eq!(prefix.len(), 77);
    prefix
}

#[test]
fn the_toy_relation_and_its_witness_generator_agree() {
    for seed in 0..8 {
        let bytes = witness(&PUBLIC, seed);
        assert_eq!(
            violated_constraints::<Gf128, _>(&Toy, &PUBLIC[..], &bytes),
            Ok(Vec::new())
        );
        assert_eq!(is_satisfied::<Gf256, _>(&Toy, &PUBLIC[..], &bytes), Ok(true));
    }
    assert_eq!(total_constraints::<Gf128, _>(&Toy), Ok(351));
    // One violated constraint per flipped output bit, at its stream index.
    let bytes = witness(&PUBLIC, 0);
    for (bit, constraint) in [
        (130, ELL),
        (162, ELL + 8),
        (196, ELL + 16),
        (239, ELL + 24),
        (272, ELL + 29),
        (294, ELL + 30),
    ] {
        let mut broken = bytes.clone();
        broken[bit / 8] ^= 1 << (bit % 8);
        assert_eq!(
            violated_constraints::<Gf256, _>(&Toy, &PUBLIC[..], &broken),
            Ok(vec![constraint])
        );
    }
    // The bit multiplied by zero is free.
    let mut free = bytes;
    free[264 / 8] ^= 1;
    assert_eq!(is_satisfied::<Gf128, _>(&Toy, &PUBLIC[..], &free), Ok(true));
}

/// Reference mode (the empty prefix) against the Python prototype.
///
/// Produced by `stage3_scratch/toy.py`, which drives an unmodified copy of the
/// validated prototype `faest.py` (the one that reproduces the official FAEST
/// v3.0.2 signature vectors on all twelve sets) through its generic interface
/// (`zk_prove`/`zk_verify` with a relation callback) with this relation, the
/// FAEST-128f and FAEST-256f rows at `ell = 320`, and the inputs below:
/// `mu[i] = 7i + 1`, `r[i] = 11i + 3`, `iv_pre[i] = 13i + 5` (mod 256). The
/// expected values are the proof length, the grinding counter and
/// SHAKE256(proof, 64 bytes).
#[test]
fn reference_mode_proofs_are_byte_identical_to_the_python_prototype() {
    const WITNESS: &str =
        "8e5727ba08417c46d9ed6cb27aebdf49af665a91073d3e8920f6f1d6827f77ff67200f72441555f0";
    fn check<F: LambdaField>(vole: &VoleParams, len: usize, counter: u32, digest: &str) {
        let level = vole.lambda();
        let context = ProofContext::reference(*vole);
        let witness = hex(WITNESS);
        let mu = pattern(2 * level.bytes(), 7, 1);
        let proof = prove::<F, _>(&context, &Toy, &PUBLIC[..], &mu, &witness, &tape(level, 0))
            .expect("valid witness");
        assert_eq!(proof.len(), len);
        assert_eq!(proof[len - 4..], counter.to_le_bytes());
        assert_eq!(shake256(&proof, 64), hex(digest), "{level:?}");
        assert_eq!(verify::<F, _>(&context, &Toy, &PUBLIC[..], &mu, &proof), Ok(()));
    }
    check::<Gf128>(
        FAEST_128F.vole(),
        3810,
        199,
        "fc7d4a214ff9db92026152f96401777ff5597929512b32cc2a5250248aadd339\
         9faf63af5986091d4197e096cf7a2e78821a025161cdb47f34c56bb179d37807",
    );
    check::<Gf256>(
        FAEST_256F.vole(),
        13068,
        891,
        "456b71f611c48b742f825a3c81488033d88ccb091d3c8a71713511bf5dddd5dc\
         86c2c334a322ed886409612af8bfdce2c1fa58870cf8cceb0043e74063cd6bdf",
    );
}

/// One proving setup: a context, a public input, `mu`, a witness and a proof.
struct Setup<'a> {
    context: ProofContext<'a>,
    public: Vec<u8>,
    mu: Vec<u8>,
    witness: Vec<u8>,
    proof: Vec<u8>,
}

fn setup<'a, F: LambdaField>(namespace: Namespace<'a>, vole: &VoleParams, salt: u8) -> Setup<'a> {
    let context = ProofContext::new(namespace, *vole);
    let public = pattern(7, 29, salt);
    let mu = message_digest(namespace, vole.lambda(), &[b"toy statement", &public])
        .expect("valid call");
    let witness = witness(&public, salt);
    let proof = prove::<F, _>(
        &context,
        &Toy,
        &public[..],
        &mu,
        &witness,
        &tape(vole.lambda(), salt),
    )
    .expect("valid witness");
    Setup {
        context,
        public,
        mu,
        witness,
        proof,
    }
}

fn accepts<F: LambdaField>(setup: &Setup<'_>, proof: &[u8]) -> Result<(), ProofError> {
    verify::<F, _>(&setup.context, &Toy, &setup.public[..], &setup.mu, proof)
}

#[test]
fn honest_proofs_verify_on_the_standard_and_on_a_custom_row() {
    let prefix = ballot_like_prefix(b"REG");
    let namespace = Namespace::new(&prefix).expect("77 bytes");
    // FAEST-128f in reference mode and namespaced; FAEST-256f geometry (the row of
    // the custom relation) namespaced, at this relation's witness length.
    let small = setup::<Gf128>(Namespace::REFERENCE, FAEST_128F.vole(), 1);
    assert_eq!(accepts::<Gf128>(&small, &small.proof), Ok(()));
    let named = setup::<Gf128>(namespace, FAEST_128F.vole(), 1);
    assert_eq!(accepts::<Gf128>(&named, &named.proof), Ok(()));
    let custom = setup::<Gf256>(namespace, FAEST_256F.vole(), 2);
    assert_eq!(accepts::<Gf256>(&custom, &custom.proof), Ok(()));

    for (setup, len) in [(&small, 3810), (&named, 3810), (&custom, 13068)] {
        assert_eq!(setup.proof.len(), len);
    }
    assert_eq!(
        custom.context.proof_bytes::<Gf256, _>(&Toy),
        Ok(custom.proof.len())
    );
    let params = custom
        .context
        .params_for::<Gf256, _>(&Toy)
        .expect("valid row");
    assert_eq!(
        (params.witness_bits(), params.constraints()),
        (320, 351)
    );
    assert_eq!(codec::proof_bytes(&params), params.signature_bytes());
}

#[test]
fn proofs_are_bound_to_the_public_input_mu_namespace_and_row() {
    let prefix = ballot_like_prefix(b"VOTE");
    let namespace = Namespace::new(&prefix).expect("77 bytes");
    let setup = setup::<Gf128>(namespace, FAEST_128F.vole(), 3);
    let Setup {
        context,
        public,
        mu,
        proof,
        ..
    } = &setup;
    assert_eq!(accepts::<Gf128>(&setup, proof), Ok(()));
    let rejected = Err(ProofError::ChallengeMismatch);

    // The public input: each kind of use (additive bit, scalar target).
    for bit in [0usize, 9, 17, 25, 33, 48] {
        let mut other = public.clone();
        other[bit / 8] ^= 1 << (bit % 8);
        assert_eq!(
            verify::<Gf128, _>(context, &Toy, &other[..], mu, proof),
            rejected,
            "public bit {bit}"
        );
    }
    // A public bit no constraint reads does not enter the check; binding it is
    // the job of `mu`, which this test keeps fixed.
    let mut unread = public.clone();
    unread[6] ^= 0x80;
    assert_eq!(
        verify::<Gf128, _>(context, &Toy, &unread[..], mu, proof),
        Ok(())
    );

    // mu.
    for at in [0, mu.len() - 1] {
        let mut other = mu.clone();
        other[at] ^= 1;
        assert_eq!(
            verify::<Gf128, _>(context, &Toy, &public[..], &other, proof),
            rejected
        );
    }

    // The namespace: reference mode, another role, a prefix one byte shorter.
    let other_prefix = ballot_like_prefix(b"REG");
    for other in [&b""[..], &other_prefix, &prefix[..76]] {
        let other = ProofContext::new(Namespace::new(other).expect("bounded"), *context.vole());
        assert_eq!(
            verify::<Gf128, _>(&other, &Toy, &public[..], mu, proof),
            rejected
        );
    }

    // The row: another leaf-commitment variant and opening budget (a different
    // proof length), and the same geometry with one more opening slot.
    for vole in [
        *FAEST_EM_128F.vole(),
        VoleParams::new(SecurityLevel::L128, 17, 8, 109, 3, 7, 312).expect("valid row"),
    ] {
        let other = ProofContext::new(namespace, vole);
        assert!(matches!(
            verify::<Gf128, _>(&other, &Toy, &public[..], mu, proof),
            Err(ProofError::Codec(CodecError::InvalidLength { .. }))
        ));
    }
    // The field must be the row's.
    assert_eq!(
        verify::<Gf256, _>(context, &Toy, &public[..], mu, proof),
        Err(ProofError::FieldMismatch {
            expected: 128,
            actual: 256
        })
    );
}

#[test]
fn an_invalid_witness_is_refused_by_the_prover_and_rejected_by_the_verifier() {
    fn check<F: LambdaField>(vole: &VoleParams, bits: &[usize]) {
        let prefix = ballot_like_prefix(b"REG");
        let namespace = Namespace::new(&prefix).expect("77 bytes");
        let setup = setup::<F>(namespace, vole, 4);
        let level = vole.lambda();
        for &bit in bits {
            let mut broken = setup.witness.clone();
            broken[bit / 8] ^= 1 << (bit % 8);
            assert_eq!(
                is_satisfied::<F, _>(&Toy, &setup.public[..], &broken),
                Ok(false)
            );
            assert_eq!(
                prove::<F, _>(
                    &setup.context,
                    &Toy,
                    &setup.public[..],
                    &setup.mu,
                    &broken,
                    &tape(level, 4)
                ),
                Err(ProofError::WitnessRejected),
                "bit {bit}"
            );
            let forged = prove_without_witness_check::<F, _>(
                &setup.context,
                &Toy,
                &setup.public[..],
                &setup.mu,
                &broken,
                &tape(level, 4),
            )
            .expect("no witness check");
            assert_eq!(forged.len(), setup.proof.len());
            assert_eq!(
                accepts::<F>(&setup, &forged),
                Err(ProofError::ChallengeMismatch),
                "bit {bit}"
            );
        }
        // The unchecked function on a valid witness is the checked one.
        let honest = prove_without_witness_check::<F, _>(
            &setup.context,
            &Toy,
            &setup.public[..],
            &setup.mu,
            &setup.witness,
            &tape(level, 4),
        )
        .expect("valid witness");
        assert_eq!(honest, setup.proof);
    }
    // One output bit of each degree on the small row, two on the large one.
    check::<Gf128>(FAEST_128F.vole(), &[130, 162, 196, 239, 272, 294]);
    check::<Gf256>(FAEST_256F.vole(), &[196, 272]);
}

/// The first, a middle and the last bit of every proof field, as
/// `(field, bit position in the proof, whether it is the field's last bit)`.
fn flips(params: &iroha_zkp_vole::params::ProofParams) -> Vec<(Field, usize, bool)> {
    let mut positions = Vec::new();
    for field in Field::ALL {
        let (offset, bits) = (field.offset(params), 8 * field.bytes(params));
        for bit in [0, bits / 2 + 3, bits - 1] {
            positions.push((field, 8 * offset + bit, bit == bits - 1));
        }
    }
    positions
}

#[test]
fn every_single_bit_flip_in_every_field_is_rejected() {
    fn check<F: LambdaField>(vole: &VoleParams, salt: u8, stride: usize) {
        let prefix = ballot_like_prefix(b"VOTE");
        let namespace = Namespace::new(&prefix).expect("77 bytes");
        let setup = setup::<F>(namespace, vole, salt);
        let params = setup.context.params_for::<F, _>(&Toy).expect("valid row");
        assert_eq!(accepts::<F>(&setup, &setup.proof), Ok(()));
        let mut seen = 0;
        for (field, bit, last) in flips(&params).into_iter().step_by(stride) {
            let mut forged = setup.proof.clone();
            forged[bit / 8] ^= 1 << (bit % 8);
            let outcome = accepts::<F>(&setup, &forged);
            assert!(outcome.is_err(), "{field:?} bit {bit}: {outcome:?}");
            // The last bit of the challenge is a grinding bit: a codec rejection.
            if field == Field::Challenge && last {
                assert!(matches!(
                    outcome,
                    Err(ProofError::Codec(CodecError::Challenge(_)))
                ));
            }
            // The counter and iv_pre are bound only through the hash chain.
            if matches!(field, Field::Counter | Field::IvPre | Field::UTilde) {
                assert_eq!(outcome, Err(ProofError::ChallengeMismatch));
            }
            seen += 1;
        }
        assert_eq!(seen, 27_usize.div_ceil(stride));
    }
    check::<Gf128>(FAEST_128F.vole(), 5, 1);
    // A thinner sample on the large row: one position per field.
    check::<Gf256>(FAEST_256F.vole(), 6, 3);
}

#[test]
fn wrong_lengths_and_non_canonical_padding_are_rejected() {
    let vole = FAEST_128F.vole();
    let lb = vole.lambda().bytes();
    // Find a proof whose opening has padding.
    let (setup, params, used) = (0u8..32)
        .find_map(|salt| {
            let setup = setup::<Gf128>(Namespace::REFERENCE, vole, salt);
            let params = setup
                .context
                .params_for::<Gf128, _>(&Toy)
                .expect("valid row");
            let fields = codec::decode(&params, &setup.proof).expect("canonical");
            let hidden = bavc::decode_challenge(vole, fields.challenge).expect("zero grinding bits");
            let nodes = bavc::opening_nodes(vole, &hidden).expect("valid pattern");
            (nodes < vole.t_open()).then_some((setup, params, nodes))
        })
        .expect("some proof opens with fewer than T_open keys");
    assert_eq!(accepts::<Gf128>(&setup, &setup.proof), Ok(()));
    let proof = &setup.proof;

    for len in [0, 1, proof.len() - 1] {
        assert_eq!(
            accepts::<Gf128>(&setup, &proof[..len]),
            Err(ProofError::Codec(CodecError::InvalidLength {
                expected: proof.len(),
                actual: len
            }))
        );
    }
    let mut longer = proof.clone();
    longer.push(0);
    assert!(matches!(
        accepts::<Gf128>(&setup, &longer),
        Err(ProofError::Codec(CodecError::InvalidLength { .. }))
    ));

    // Every padding byte position class: first, second, last.
    let start = Field::Decommitment.offset(&params) + (vole.tau() * vole.n_leafcom() + used) * lb;
    let end = Field::Challenge.offset(&params);
    assert!(start < end);
    assert!(proof[start..end].iter().all(|&byte| byte == 0));
    for at in [start, start + 1, end - 1] {
        for value in [1u8, 0x80] {
            let mut forged = proof.clone();
            forged[at] = value;
            assert_eq!(
                accepts::<Gf128>(&setup, &forged),
                Err(ProofError::Codec(CodecError::NonZeroPadding {
                    field: Field::Decommitment
                }))
            );
        }
    }
}

#[test]
fn proofs_are_deterministic_in_the_tape_and_differ_across_tapes() {
    let vole = FAEST_128F.vole();
    let level = vole.lambda();
    let first = setup::<Gf128>(Namespace::REFERENCE, vole, 7);
    let again = setup::<Gf128>(Namespace::REFERENCE, vole, 7);
    assert_eq!(first.proof, again.proof);

    let prove_with = |tape: &Tape| {
        prove::<Gf128, _>(
            &first.context,
            &Toy,
            &first.public[..],
            &first.mu,
            &first.witness,
            tape,
        )
        .expect("valid witness")
    };
    let root = pattern(level.bytes(), 11, 10);
    let iv_pre: [u8; 16] = pattern(16, 13, 12).try_into().expect("16 bytes");
    assert_eq!(prove_with(&tape(level, 7)), first.proof);

    // Another root seed with the same iv_pre, and the same seed with another
    // iv_pre: other bytes, and each still verifies.
    let mut other_root = root.clone();
    other_root[0] ^= 1;
    let mut other_iv = iv_pre;
    other_iv[15] ^= 0x80;
    let mut proofs = vec![first.proof.clone()];
    for (root, iv_pre) in [(&root, &other_iv), (&other_root, &iv_pre), (&other_root, &other_iv)] {
        let proof = prove_with(&Tape::explicit(level, root, iv_pre).expect("valid tape"));
        assert_eq!(accepts::<Gf128>(&first, &proof), Ok(()));
        proofs.push(proof);
    }
    assert_eq!(root, tape(level, 7).root());
    assert_eq!(&iv_pre, tape(level, 7).iv_pre());
    for (i, left) in proofs.iter().enumerate() {
        for right in &proofs[i + 1..] {
            assert_ne!(left, right);
            // Not merely the trailing fields: the corrections differ as well.
            assert_ne!(left[..64], right[..64]);
        }
    }

    // A tape derived through H_3 works like an explicit one.
    let derived = Tape::derive(Namespace::REFERENCE, level, &first.witness[..16], &first.mu, &[0; 16])
        .expect("valid inputs");
    let proof = prove_with(&derived);
    assert_eq!(accepts::<Gf128>(&first, &proof), Ok(()));
    assert_eq!(proof, prove_with(&derived));
}

/// `T_crt` of section 6.1 of the ballot profile: SHAKE256 with 64 output bytes of
/// the canonical word string of the table set, each word as eight little-endian
/// bytes.
#[test]
fn the_crt_tables_of_the_ballot_rows_have_the_digests_of_the_profile() {
    for (set, bytes, digest) in [
        (
            FAEST_256F,
            84_304,
            "a9c572a7c8f2cc735218123c6456e1e016e78b06aa2d03192ef801bf7fdb93ae\
             014a9e16555e6bad81382c630467e45e76c9b1c3948f9dfea41a7a1435bcffea",
        ),
        (
            FAEST_256S,
            83_704,
            "792f81bf102cac84b7c559595342b6b23ad27dab9065651feb928dd0a649a3f4\
             bd1da3d350fbd4c62f1707d441d46ef084430b5f00b53a1af7088281d6a7386e",
        ),
    ] {
        let tables = set.vole().crt_tables().expect("embedded tables");
        let serialised: Vec<u8> = encode_words(tables)
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        assert_eq!(serialised.len(), bytes, "{}", set.name());
        assert_eq!(&serialised[..8], b"FAESTCRT");
        assert_eq!(shake256(&serialised, 64), hex(digest), "{}", set.name());
    }
}

#[test]
fn the_scalars_of_the_toy_relation_are_the_powers_of_the_seed() {
    let powers = scalars::<Gf128>();
    assert_eq!(powers[0], Gf128::from_u64(SCALAR_SEED));
    assert_eq!(powers[1], powers[0].square());
    assert_eq!(powers[15], powers[7].square());
    assert!(public_bit(&PUBLIC, 0) && !public_bit(&PUBLIC, 1) && !public_bit(&PUBLIC, 999));
}
