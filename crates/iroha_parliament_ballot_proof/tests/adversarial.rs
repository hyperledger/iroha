//! Reproducible, bounded mutation campaign for standalone statement and proof inputs.
//!
//! A pinned corpus/acceptance digest must agree in portable and accelerated builds:
//! one covers both rows (with the `diagnostics` feature), one the candidate row of
//! production builds.
//! This does not establish exhaustive fuzz coverage, memory ceilings, or security
//! qualification. Run with `--release --test adversarial -- --nocapture`.

mod common;

use std::panic::{UnwindSafe, catch_unwind};

use common::{reg_case, vote_case};
use iroha_parliament_ballot_proof::{
    credential::body_digest,
    framing::{BodyContext, frame_bytes},
    profile::{Profile, ProofField, Role, Row},
    proving::StatementError,
    registration,
    sealed_list::ListError,
    test_codec::{self, TestCodecError},
    vote,
};
use iroha_zkp_vole::{codec, params::ProofParams, variant::Construction};
use sha3::{Digest, Sha3_256};

const SEED: u64 = 0x5041_524c_4241_4c4c;

struct Campaign {
    state: u64,
    digest: Sha3_256,
    cases: usize,
    accepted: usize,
}

impl Campaign {
    fn new() -> Self {
        let mut digest = Sha3_256::new();
        digest.update(b"parliament/ballot/adversarial/v1");
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
            "ballot seed={SEED:#x} cases={} true_outcomes={} false_outcomes={} sha3_256={digest}",
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

fn decode_statement(profile: &Profile, role: Role, bytes: &[u8]) -> bool {
    let canonical = match role {
        Role::Registration => test_codec::decode_registration(profile, bytes)
            .and_then(|statement| test_codec::encode_registration(profile, &statement)),
        Role::Vote => test_codec::decode_vote(profile, bytes)
            .and_then(|statement| test_codec::encode_vote(profile, &statement)),
    };
    canonical.is_ok_and(|encoded| {
        assert_eq!(
            encoded, bytes,
            "an accepted statement must encode identically"
        );
        true
    })
}

/// Read length-word offsets and owned fields from an already trusted frame.
fn frame_fields(bytes: &[u8]) -> (Vec<usize>, Vec<Vec<u8>>) {
    let tag_len = usize::from(u16::from_le_bytes(bytes[..2].try_into().expect("u16")));
    let mut at = 2 + tag_len;
    let count = usize::from(u16::from_le_bytes(
        bytes[at..at + 2].try_into().expect("u16"),
    ));
    at += 2;
    let mut offsets = Vec::with_capacity(count);
    let mut fields = Vec::with_capacity(count);
    for _ in 0..count {
        offsets.push(at);
        let len = usize::try_from(u32::from_le_bytes(
            bytes[at..at + 4].try_into().expect("u32"),
        ))
        .expect("bounded");
        at += 4;
        fields.push(bytes[at..at + len].to_vec());
        at += len;
    }
    assert_eq!(at, bytes.len());
    (offsets, fields)
}

fn reframe(role: Role, fields: &[Vec<u8>]) -> Vec<u8> {
    let tag = match role {
        Role::Registration => test_codec::REGISTRATION_TAG,
        Role::Vote => test_codec::VOTE_TAG,
    };
    frame_bytes(tag, &fields.iter().map(Vec::as_slice).collect::<Vec<_>>()).expect("bounded frame")
}

fn statements(
    campaign: &mut Campaign,
    profile: &Profile,
    role: Role,
    statement: &[u8],
    proof: &[u8],
) {
    let decode = |bytes: &[u8]| decode_statement(profile, role, bytes);
    assert!(campaign.record("valid/statement", statement, || decode(statement)));
    let (offsets, original) = frame_fields(statement);
    // Every truncation of these small, valid registration/S=3 statements.
    for cut in 0..statement.len() {
        assert!(
            !campaign.record("truncated/statement", &statement[..cut], || decode(
                &statement[..cut]
            ))
        );
    }
    for offset in offsets {
        for length in [0, 1, 127, 128, 129, 4096, 4097, u32::MAX] {
            let mut mutant = statement.to_vec();
            mutant[offset..offset + 4].copy_from_slice(&length.to_le_bytes());
            campaign.record("length-word/statement", &mutant, || decode(&mutant));
        }
    }
    for _ in 0..256 {
        let mut mutant = statement.to_vec();
        let at = campaign.choose(mutant.len());
        mutant[at] ^= 1 << campaign.choose(8);
        campaign.record("bit/statement", &mutant, || decode(&mutant));
    }
    let mut trailing = statement.to_vec();
    trailing.push(0);
    assert!(!campaign.record("trailing/statement", &trailing, || decode(&trailing)));
    for _ in 0..128 {
        let mut bytes = vec![0; campaign.choose(1024)];
        for byte in &mut bytes {
            *byte = u8::try_from(campaign.choose(256)).expect("byte");
        }
        assert!(!campaign.record("garbage/statement", &bytes, || decode(&bytes)));
    }
    match role {
        Role::Registration => {
            for (field, cap) in [(1, 4096), (2, 256)] {
                for len in [cap, cap + 1] {
                    let mut fields = original.clone();
                    fields[field] = vec![0x42; len];
                    if field == 1 && len == cap {
                        fields[8] = body_digest(&BodyContext::new(&fields[1]).expect("at cap"))
                            .expect("digest")
                            .as_bytes()
                            .to_vec();
                    }
                    let mutant = reframe(role, &fields);
                    assert_eq!(
                        campaign.record("allocation-cap/statement", &mutant, || decode(&mutant)),
                        len == cap
                    );
                }
            }
        }
        Role::Vote => {
            for entries in [0, 1, 2, 1001] {
                let mut fields = original.clone();
                fields[4] = u16::try_from(entries)
                    .expect("bounded")
                    .to_le_bytes()
                    .to_vec();
                fields[5] = vec![0; entries * 128];
                let mutant = reframe(role, &fields);
                assert_eq!(
                    test_codec::decode_vote(profile, &mutant),
                    Err(TestCodecError::Statement(StatementError::List(
                        ListError::Size { actual: entries }
                    )))
                );
                assert!(!campaign.record("list-cap/statement", &mutant, || decode(&mutant)));
            }
        }
    }
    let record = test_codec::encode_record(statement, proof).expect("bounded");
    let decode_record = |bytes: &[u8]| {
        test_codec::decode_record(profile, role, bytes)
            .is_ok_and(|(statement, _)| decode(statement))
    };
    assert!(campaign.record("valid/record", &record, || decode_record(&record)));
    for cut in [
        0,
        3,
        4,
        statement.len(),
        4 + statement.len(),
        record.len() - 1,
    ] {
        assert!(
            !campaign.record("truncated/record", &record[..cut], || decode_record(
                &record[..cut]
            ))
        );
    }
    for offset in [0, 4 + statement.len()] {
        for length in [0, 1, 128, u32::MAX] {
            let mut mutant = record.clone();
            mutant[offset..offset + 4].copy_from_slice(&length.to_le_bytes());
            assert!(!campaign.record("length-word/record", &mutant, || decode_record(&mutant)));
        }
    }
    let mut trailing = record;
    trailing.push(0);
    assert!(!campaign.record("trailing/record", &trailing, || decode_record(&trailing)));
}

fn proof_campaign(
    campaign: &mut Campaign,
    row: Row,
    role: Role,
    proof: &[u8],
    verify: impl Fn(&[u8]) -> bool + std::panic::RefUnwindSafe,
) {
    let params =
        ProofParams::new(row.vole(), role.witness_bits(), role.constraints()).expect("supported");
    let parse = |bytes: &[u8]| codec::decode_as(Construction::Extended, &params, bytes).is_ok();
    assert!(campaign.record("valid/proof", proof, || verify(proof)));
    for segment in row.proof_layout(role) {
        for cut in [segment.offset, segment.offset + segment.len - 1] {
            assert!(!campaign.record("truncated/proof", &proof[..cut], || verify(&proof[..cut])));
        }
    }
    for _ in 0..128 {
        let mut mutant = proof.to_vec();
        let at = campaign.choose(mutant.len());
        mutant[at] ^= 1 << campaign.choose(8);
        campaign.record("bit/proof-parser", &mutant, || parse(&mutant));
    }
    for field in [
        ProofField::Coefficients,
        ProofField::HiddenLeafCommitments,
        ProofField::Salt,
    ] {
        let segment = row
            .proof_layout(role)
            .into_iter()
            .find(|segment| segment.field == field)
            .expect("present");
        let mut mutant = proof.to_vec();
        let offset = if field == ProofField::HiddenLeafCommitments {
            96
        } else {
            0
        };
        mutant[segment.offset + offset] ^= 1;
        assert!(
            parse(&mutant),
            "late-invalid corpus must reach reconstruction"
        );
        assert!(!campaign.record("late-invalid/proof", &mutant, || verify(&mutant)));
    }
    let mut counter = proof.to_vec();
    let last = counter.len() - 4;
    for value in [0x0010_0000u32, u32::MAX] {
        counter[last..].copy_from_slice(&value.to_le_bytes());
        assert!(!campaign.record("counter/proof", &counter, || verify(&counter)));
    }
    let mut trailing = proof.to_vec();
    trailing.push(0);
    assert!(!campaign.record("trailing/proof", &trailing, || verify(&trailing)));
}

#[test]
fn seeded_statements_records_and_proofs_campaign() {
    println!(
        "layout bytes: Gf256={} Key<Gf256>={} usize={}",
        core::mem::size_of::<iroha_zkp_vole::field::Gf256>(),
        core::mem::size_of::<iroha_zkp_vole::quicksilver::Key<iroha_zkp_vole::field::Gf256>>(),
        core::mem::size_of::<usize>()
    );
    let mut campaign = Campaign::new();
    for row in Row::ALL {
        let profile = Profile::new(row).expect("supported");
        let case = reg_case(row);
        let proof: &[u8] = match row {
            Row::Candidate => include_bytes!("fixtures/reg_fast.proof"),
            #[cfg(feature = "diagnostics")]
            Row::Comparator => include_bytes!("fixtures/reg_comparator.proof"),
        };
        let encoded = test_codec::encode_registration(&profile, &case.statement).expect("valid");
        statements(&mut campaign, &profile, Role::Registration, &encoded, proof);
        proof_campaign(&mut campaign, row, Role::Registration, proof, |bytes| {
            registration::verify(row, &case.statement, bytes).is_ok()
        });
        let case = vote_case(row, 3, 1);
        let proof: &[u8] = match row {
            Row::Candidate => include_bytes!("fixtures/vote_S3_i1_fast.proof"),
            #[cfg(feature = "diagnostics")]
            Row::Comparator => include_bytes!("fixtures/vote_S3_i1_comparator.proof"),
        };
        let encoded = test_codec::encode_vote(&profile, &case.statement).expect("valid");
        statements(&mut campaign, &profile, Role::Vote, &encoded, proof);
        proof_campaign(&mut campaign, row, Role::Vote, proof, |bytes| {
            vote::verify(row, &case.statement, bytes).is_ok()
        });
        for size in [500, 1000] {
            let case = vote_case(row, size, size / 2);
            let bytes = test_codec::encode_vote(&profile, &case.statement).expect("valid");
            assert!(
                campaign.record("large-list/statement", &bytes, || decode_statement(
                    &profile,
                    Role::Vote,
                    &bytes
                ))
            );
        }
    }
    campaign.finish(CAMPAIGN_DIGEST);
}

/// The pinned digest of the campaign over both rows (`diagnostics` feature).
#[cfg(feature = "diagnostics")]
const CAMPAIGN_DIGEST: &str = "cace017fe544236ec94320349a6a6617c8df88d2ae0e149ce767c73dbad2a862";

/// The pinned digest of the candidate-row campaign of production builds.
#[cfg(not(feature = "diagnostics"))]
const CAMPAIGN_DIGEST: &str = "CANDIDATE_ONLY_DIGEST_TO_PIN";
