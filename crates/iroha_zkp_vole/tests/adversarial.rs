//! Bounded, deterministic mutation campaign for the backend's untrusted inputs.
//!
//! The fixed seed and corpus/result digest make the portable and accelerated runs
//! directly comparable. This is regression evidence, not exhaustive fuzzing or a
//! security qualification. Run with `--release --test adversarial -- --nocapture`.

mod common;

use std::panic::{UnwindSafe, catch_unwind};

use common::Fixture;
use iroha_zkp_vole::{
    bavc,
    codec::{self, Field},
    faest,
    field::Gf256,
    hash::Namespace,
    params::{FAEST_256F, FAEST_256S, FAEST_PARAMETER_SETS, ProofParams},
    proof::{self, ProofContext},
    quicksilver::{ConstraintSystem, Relation},
    randomness::Tape,
    variant::{Construction, EXTENDED_LAST_COUNTER},
};
use sha3::{Digest, Sha3_256};

const SEED: u64 = 0x5041_524c_4241_434b;

struct Campaign {
    state: u64,
    digest: Sha3_256,
    cases: usize,
    accepted: usize,
}

impl Campaign {
    fn new() -> Self {
        let mut digest = Sha3_256::new();
        digest.update(b"parliament/backend/adversarial/v1");
        digest.update(SEED.to_le_bytes());
        Self {
            state: SEED,
            digest,
            cases: 0,
            accepted: 0,
        }
    }

    fn choose(&mut self, bound: usize) -> usize {
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
        usize::try_from(self.state % u64::try_from(bound).expect("bounded")).expect("bounded")
    }

    fn record(
        &mut self,
        label: &str,
        bytes: &[u8],
        call: impl FnOnce() -> bool + UnwindSafe,
    ) -> bool {
        let accepted = catch_unwind(call)
            .unwrap_or_else(|_| panic!("seed {SEED:#x}, case {} ({label}) panicked", self.cases));
        self.digest
            .update(u64::try_from(label.len()).expect("bounded").to_le_bytes());
        self.digest.update(label.as_bytes());
        self.digest
            .update(u64::try_from(bytes.len()).expect("bounded").to_le_bytes());
        self.digest.update(Sha3_256::digest(bytes));
        self.digest.update([u8::from(accepted)]);
        self.cases += 1;
        self.accepted += usize::from(accepted);
        accepted
    }

    fn finish(self, expected: &str) {
        let digest = format!("{:x}", self.digest.finalize());
        println!(
            "backend seed={SEED:#x} cases={} true_outcomes={} false_outcomes={} sha3_256={digest}",
            self.cases,
            self.accepted,
            self.cases - self.accepted
        );
        println!(
            "true_outcomes includes syntactic parser acceptance; every designated invalid proof was rejected by verification"
        );
        assert_eq!(digest, expected);
    }
}

fn parser_campaign(
    campaign: &mut Campaign,
    construction: Construction,
    params: &ProofParams,
    proof: &[u8],
) {
    let parse = |bytes: &[u8]| codec::decode_as(construction, params, bytes).is_ok();
    assert!(campaign.record("valid/codec", proof, || parse(proof)));
    for field in Field::all(construction) {
        let start = field.offset_as(construction, params);
        let end = start + field.bytes_as(construction, params);
        for cut in [start, end - 1] {
            assert!(!campaign.record("truncated/codec", &proof[..cut], || parse(&proof[..cut])));
        }
    }
    let mut trailing = proof.to_vec();
    trailing.push(0);
    assert!(!campaign.record("trailing/codec", &trailing, || parse(&trailing)));
    for _ in 0..128 {
        let mut mutant = proof.to_vec();
        let index = campaign.choose(mutant.len());
        mutant[index] ^= 1 << campaign.choose(8);
        campaign.record("bit/codec", &mutant, || parse(&mutant));
    }
    for _ in 0..64 {
        let mut garbage = vec![0; campaign.choose(512)];
        for byte in &mut garbage {
            *byte = u8::try_from(campaign.choose(256)).expect("byte");
        }
        assert!(!campaign.record("garbage/codec", &garbage, || parse(&garbage)));
    }
    let counter = Field::Counter.offset_as(construction, params);
    for value in [
        0,
        EXTENDED_LAST_COUNTER,
        EXTENDED_LAST_COUNTER + 1,
        u32::MAX,
    ] {
        let mut mutant = proof.to_vec();
        mutant[counter..].copy_from_slice(&value.to_le_bytes());
        let accepted = campaign.record("counter/codec", &mutant, || parse(&mutant));
        assert_eq!(accepted, value <= construction.last_counter());
    }
    let vole = params.vole();
    let fields = codec::decode_as(construction, params, proof).expect("valid");
    let hidden = bavc::decode_challenge(vole, fields.challenge).expect("admissible");
    let nodes = bavc::opening_nodes(vole, &hidden).expect("admissible");
    let opening_start = Field::Decommitment.offset_as(construction, params);
    let used = vole.tau() * bavc::leaf_commitment_bytes(construction, vole)
        + nodes * vole.lambda().bytes();
    for offset in [used, fields.decommitment.len().saturating_sub(1)] {
        if offset >= used && offset < fields.decommitment.len() {
            let mut mutant = proof.to_vec();
            mutant[opening_start + offset] = 1;
            assert!(!campaign.record("opening-padding/codec", &mutant, || parse(&mutant)));
        }
    }
    if !vole.n_mult().is_multiple_of(8) {
        let row_bytes = vole.n_mult().div_ceil(8);
        for row in 0..vole.n_mask() {
            let mut mutant = proof.to_vec();
            let at = Field::MultCorrections.offset_as(construction, params)
                + row * row_bytes
                + row_bytes
                - 1;
            mutant[at] |= 0x80;
            assert!(!campaign.record("mask-padding/codec", &mutant, || parse(&mutant)));
        }
    }
    let mut grinding = proof.to_vec();
    grinding[Field::Challenge.offset_as(construction, params) + vole.lambda().bytes() - 1] |= 0x80;
    assert!(!campaign.record("grinding/codec", &grinding, || parse(&grinding)));
}

struct Free;

impl Relation<Gf256> for Free {
    type PublicInput = ();
    fn witness_bits(&self) -> usize {
        256
    }
    fn constraints(&self) -> usize {
        0
    }
    fn emit<C: ConstraintSystem<Field = Gf256>>(&self, _public: &(), _cs: &mut C) {}
}

#[test]
fn seeded_parser_and_reconstruction_campaign() {
    let mut campaign = Campaign::new();
    let fixture = Fixture::load("faest_tvs");
    let message = fixture.bytes("faest_tvs.message");
    for set in FAEST_PARAMETER_SETS {
        let name = set.name().to_ascii_lowercase().replace('-', "_");
        let signature = fixture.bytes(&format!("faest_tvs.{name}.signature"));
        let key = fixture.bytes(&format!("faest_tvs.{name}.pk"));
        parser_campaign(&mut campaign, Construction::Faest, set.proof(), &signature);
        assert!(campaign.record("valid/reference", &signature, || {
            faest::verify(&set, &key, &message, &signature).is_ok()
        }));
        let mut late = signature.clone();
        late[Field::Coefficients.offset(set.proof())] ^= 1;
        assert!(codec::decode(set.proof(), &late).is_ok());
        assert!(!campaign.record("late-invalid/reference", &late, || {
            faest::verify(&set, &key, &message, &late).is_ok()
        }));
    }
    let namespace = Namespace::new(b"PARL/ADVERSARIAL/v1").expect("bounded");
    for set in [FAEST_256F, FAEST_256S] {
        let context = ProofContext::extended(namespace, *set.vole()).expect("supported");
        let params = context.params_for::<Gf256, _>(&Free).expect("supported");
        let tape = Tape::extended(set.vole().lambda(), &[0x31; 32], &[0x42; 16], &[0x53; 32])
            .expect("sized");
        let mu = [0x64; 64];
        let proof =
            proof::prove::<Gf256, _>(&context, &Free, &(), &mu, &[0x75; 32], &tape).expect("valid");
        parser_campaign(&mut campaign, Construction::Extended, &params, &proof);
        assert!(campaign.record("valid/extended", &proof, || {
            proof::verify::<Gf256, _>(&context, &Free, &(), &mu, &proof).is_ok()
        }));
        for field in [
            Field::Coefficients,
            Field::MaskedWitness,
            Field::Salt,
            Field::Decommitment,
        ] {
            let mut late = proof.clone();
            late[field.offset_as(Construction::Extended, &params)] ^= 1;
            assert!(codec::decode_as(Construction::Extended, &params, &late).is_ok());
            assert!(!campaign.record("late-invalid/extended", &late, || {
                proof::verify::<Gf256, _>(&context, &Free, &(), &mu, &late).is_ok()
            }));
        }
    }
    campaign.finish("dda625d9e970dfc0651e76f5627a89684fa88f2319af5a7b371e73195e2b7c1b");
}
