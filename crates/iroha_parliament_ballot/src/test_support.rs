//! Deterministic fixtures shared by this crate's tests.
//!
//! The fixture ballots use fixed credential secrets and fixed proving tapes, so their proof
//! bytes, and therefore their stamp payloads, are reproducible. Mining a 28-bit stamp takes
//! about `2^28` SHA3-512 evaluations, far too slow for a debug test, so each fixture's nonce
//! was mined once and is pinned in [`FIXTURE_BALLOTS`] and [`FORGED_NONCE`]; every test run
//! verifies the pinned nonces with the data model's stamp verification at the real frozen
//! difficulty. `regenerate_fixture_stamps` (ignored) re-mines them after a deliberate change
//! of a fixture input:
//!
//! ```text
//! cargo test --release -p iroha_parliament_ballot -- --ignored regenerate_fixture_stamps --nocapture
//! ```

use std::sync::{Arc, OnceLock};

use iroha_data_model::{
    NetworkId,
    account::AccountId,
    block::BlockHeader,
    governance::{
        anonymous_ballot::{
            AdmissionNonceV1, AdmissionStampV1, AnonymousBallotAuthorizationV1,
            AnonymousBallotEnvelopeV1, AnonymousBallotV1, BallotBodyContextV1, BallotChoiceV1,
            BallotProofBytesV1, CanonicalAnonymousBallotEnvelopeV1, CredentialCommitmentV1,
            Digest512, FrozenBallotPolicyV1, FrozenParliamentAttemptPolicyV1,
            ParliamentBallotParametersV1, ParliamentLifecycleParametersV1, ProofProfileIdV1,
            SealedCredentialListV1, digests::proposal_digest_v1,
        },
        types::{
            AbiVersion, BodyElectionAttemptId, BodyInstanceId, ContractAbiHash, ContractCodeHash,
            DeployContractProposal, GovernanceAttemptId, ParliamentBody, ProposalContentId,
            ProposalKind, RiskTierV1,
        },
    },
    prelude::{Hash, HashOf},
};
use iroha_parliament_ballot_proof::{
    credential::CredentialSecret, proving::ProvingTape, vote, vote::VoteStatement,
};

use crate::{
    PROOF_ROW_V1,
    context::ScopedBallotContextV1,
    inputs::{ProofValueV1, body_digest_v1, proof_profile_v1},
};

/// Sealed seats of the fixture roster.
pub const SEATS: u8 = 4;

/// A fixed Ed25519 account.
pub fn account() -> AccountId {
    AccountId::new(
        "ed0120BDF918243253B1E731FA096194C8928DA37C4D3226F97EEBD18CF5523D758D6C"
            .parse()
            .expect("public key"),
    )
}

/// The fixture network.
pub fn network_id() -> NetworkId {
    NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
        Hash::prehashed([0x5a; Hash::LENGTH]),
    ))
}

/// Another network.
pub fn other_network_id() -> NetworkId {
    NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
        Hash::prehashed([0x5b; Hash::LENGTH]),
    ))
}

/// The Policy Jury body context of the fixture attempt.
pub fn body_context() -> BallotBodyContextV1 {
    BallotBodyContextV1 {
        network_id: network_id(),
        governance_attempt_id: GovernanceAttemptId::new([0x11; 32]),
        election_attempt_id: BodyElectionAttemptId::new([0x22; 32]),
        body_role: ParliamentBody::PolicyJury,
    }
}

/// The sealed body instance.
pub fn body_instance_id() -> BodyInstanceId {
    BodyInstanceId::new([0x03; 32])
}

/// The proposal content identifier recorded at closure.
pub fn proposal_content_id() -> ProposalContentId {
    ProposalContentId::new([0x01; 32])
}

/// A fixed contract-deployment proposal.
pub fn proposal() -> ProposalKind {
    ProposalKind::DeployContract(DeployContractProposal {
        proposal_operator: account(),
        contract_address: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw"
            .parse()
            .expect("contract address"),
        code_hash: ContractCodeHash::new([0xaa; 32]),
        abi_hash: ContractAbiHash::new([0xbb; 32]),
        abi_version: AbiVersion::new(1),
        manifest_provenance: None,
    })
}

/// `proposal_digest` of [`proposal`].
pub fn proposal_digest() -> Digest512 {
    proposal_digest_v1(&proposal()).expect("proposal digest")
}

/// The SCCP-route pipeline with its conditional Confirmation Jury.
pub fn pipeline() -> Vec<ParliamentBody> {
    vec![
        ParliamentBody::RulesCommittee,
        ParliamentBody::AgendaCouncil,
        ParliamentBody::InterestPanel,
        ParliamentBody::ReviewPanel,
        ParliamentBody::CoordinationCouncil,
        ParliamentBody::FmaCommittee,
        ParliamentBody::OversightCommittee,
        ParliamentBody::PolicyJury,
        ParliamentBody::ConfirmationJury,
    ]
}

/// The attempt snapshot of [`pipeline`] frozen from the default committed lifecycle and
/// ballot parameters at a 1,000 ms block cadence and the default 3,600-block pulse cadence.
pub fn attempt_policy() -> FrozenParliamentAttemptPolicyV1 {
    FrozenParliamentAttemptPolicyV1::freeze_v1(
        &pipeline(),
        &ParliamentLifecycleParametersV1::default(),
        Some(&ParliamentBallotParametersV1::default()),
        1_000,
        3_600,
    )
    .expect("default attempt policy")
}

/// The Policy Jury snapshot of a standard-tier [`attempt_policy`] (28-bit stamps, a one-day
/// casting window).
pub fn policy() -> FrozenBallotPolicyV1 {
    attempt_policy()
        .ballot_policy(RiskTierV1::Standard, ParliamentBody::PolicyJury)
        .expect("default ballot policy")
}

/// The credential secret of roster member `member`.
pub const fn secret_bytes(member: u8) -> [u8; 48] {
    [0x40 + member; 48]
}

/// The commitment of `secret` to the fixture body.
pub fn commitment_of(secret: &[u8; 48]) -> CredentialCommitmentV1 {
    let body = body_digest_v1(&body_context()).expect("B");
    CredentialCommitmentV1::from_proof(
        &CredentialSecret::from_bytes(secret).commitment(&body.to_proof()),
    )
}

/// The sealed list of the [`SEATS`] fixture members.
pub fn sealed_list() -> SealedCredentialListV1 {
    let body = body_digest_v1(&body_context()).expect("B");
    SealedCredentialListV1::from_unsorted(
        ProofProfileIdV1::V1,
        body,
        (0..SEATS)
            .map(|member| commitment_of(&secret_bytes(member)))
            .collect(),
    )
    .expect("sorted fixture list")
}

/// The scoped verification context of the fixture body, built once.
pub fn scoped_context() -> Arc<ScopedBallotContextV1> {
    static CONTEXT: OnceLock<Arc<ScopedBallotContextV1>> = OnceLock::new();
    CONTEXT
        .get_or_init(|| {
            Arc::new(
                ScopedBallotContextV1::build(
                    body_context(),
                    proposal_digest(),
                    body_instance_id(),
                    &sealed_list(),
                    policy(),
                )
                .expect("fixture context"),
            )
        })
        .clone()
}

/// The fixed proving tape `tag`.
pub const fn tape(tag: u8) -> [u8; 112] {
    [tag; 112]
}

/// The nonce `offset` from the zero nonce: `offset` little-endian in the first eight bytes.
/// Each pinned nonce is the smallest such offset whose work digest reaches 28 bits, found
/// once with a multi-threaded release-mode search of the same work frame.
const fn offset_nonce(offset: u64) -> [u8; 32] {
    let bytes = offset.to_le_bytes();
    let mut out = [0_u8; 32];
    let mut index = 0;
    while index < bytes.len() {
        out[index] = bytes[index];
        index += 1;
    }
    out
}

/// One fixture ballot: a member's choice proved with a fixed tape, and its pinned stamp.
#[derive(Debug, Clone, Copy)]
pub struct FixtureBallot {
    /// Roster member whose credential casts the ballot.
    pub member: u8,
    /// The choice.
    pub vote: BallotChoiceV1,
    /// Proving-tape tag.
    pub tape: u8,
    /// Pinned 28-bit stamp nonce.
    pub nonce: [u8; 32],
}

/// Member 0 votes Aye.
pub const AYE_0: usize = 0;
/// Member 1 votes Nay.
pub const NAY_1: usize = 1;
/// Member 2 votes Aye.
pub const AYE_2: usize = 2;
/// Member 3 abstains.
pub const ABSTAIN_3: usize = 3;
/// Member 0 again, with the conflicting choice Nay: the same nullifier as [`AYE_0`].
pub const NAY_0: usize = 4;

/// The fixture ballots and their pinned stamp nonces.
pub const FIXTURE_BALLOTS: [FixtureBallot; 5] = [
    FixtureBallot {
        member: 0,
        vote: BallotChoiceV1::Aye,
        tape: 0x10,
        nonce: offset_nonce(110_609_495),
    },
    FixtureBallot {
        member: 1,
        vote: BallotChoiceV1::Nay,
        tape: 0x11,
        nonce: offset_nonce(400_695_293),
    },
    FixtureBallot {
        member: 2,
        vote: BallotChoiceV1::Aye,
        tape: 0x12,
        nonce: offset_nonce(812_400_381),
    },
    FixtureBallot {
        member: 3,
        vote: BallotChoiceV1::Abstain,
        tape: 0x13,
        nonce: offset_nonce(153_706_119),
    },
    FixtureBallot {
        member: 0,
        vote: BallotChoiceV1::Nay,
        tape: 0x14,
        nonce: offset_nonce(213_200_714),
    },
];

/// Byte of [`NAY_1`]'s proof flipped in the forged ballot.
pub const FORGED_PROOF_BYTE: usize = 1_000;

/// Pinned 28-bit stamp nonce of the forged ballot.
pub const FORGED_NONCE: [u8; 32] = offset_nonce(202_597_833);

/// The authorization (every field but the stamp) of fixture ballot `index`, proved once.
pub fn fixture_authorization(index: usize) -> AnonymousBallotAuthorizationV1 {
    static PROOFS: [OnceLock<AnonymousBallotAuthorizationV1>; 5] = [const { OnceLock::new() }; 5];
    PROOFS[index]
        .get_or_init(|| prove_fixture(&FIXTURE_BALLOTS[index]))
        .clone()
}

/// Prove a fixture ballot directly through the proof crate, independently of the wallet.
fn prove_fixture(ballot: &FixtureBallot) -> AnonymousBallotAuthorizationV1 {
    let context = scoped_context();
    let profile = proof_profile_v1().expect("profile");
    let secret = CredentialSecret::from_bytes(&secret_bytes(ballot.member));
    let list = crate::inputs::proof_list_v1(&context.context().sealed_list().expect("list"))
        .expect("list");
    let body = context.context().body_context_digest.to_proof();
    let statement = VoteStatement::for_secret(
        &profile,
        &secret,
        body,
        context.scope().to_proof(),
        &list,
        ballot.vote.to_proof(),
        context.policy_hash().to_proof(),
    )
    .expect("statement");
    let position = list
        .position(&secret.commitment(&body))
        .expect("the member is sealed");
    let proof = vote::prove(
        PROOF_ROW_V1,
        &statement,
        &secret,
        position,
        ProvingTape::from_bytes(&tape(ballot.tape)),
    )
    .expect("honest proof");
    AnonymousBallotAuthorizationV1 {
        network_id: *context.network_id(),
        scope: *context.scope(),
        vote: ballot.vote,
        nullifier: ProofValueV1::from_proof(&statement.nullifier),
        auth_v: ProofValueV1::from_proof(&statement.auth_v),
        profile_id: ProofProfileIdV1::V1,
        proof: BallotProofBytesV1::new(proof).expect("exact length"),
    }
}

/// The envelope of `authorization` stamped with `nonce`.
pub fn envelope_of(
    authorization: &AnonymousBallotAuthorizationV1,
    nonce: [u8; 32],
) -> AnonymousBallotEnvelopeV1 {
    AnonymousBallotEnvelopeV1 {
        network_id: authorization.network_id,
        ballot: AnonymousBallotV1 {
            scope: authorization.scope,
            vote: authorization.vote,
            nullifier: authorization.nullifier,
            auth_v: authorization.auth_v,
            profile_id: authorization.profile_id,
            stamp: AdmissionStampV1 {
                nonce: AdmissionNonceV1::new(nonce),
            },
            proof: authorization.proof.clone(),
        },
    }
}

/// Fixture ballot `index` with its pinned stamp.
pub fn fixture_envelope(index: usize) -> AnonymousBallotEnvelopeV1 {
    envelope_of(&fixture_authorization(index), FIXTURE_BALLOTS[index].nonce)
}

/// The canonical frame of fixture ballot `index`.
pub fn fixture_bytes(index: usize) -> Vec<u8> {
    CanonicalAnonymousBallotEnvelopeV1::from_envelope(&fixture_envelope(index))
        .expect("canonical")
        .as_bytes()
        .to_vec()
}

/// The authorization of [`NAY_1`] with one proof byte flipped.
pub fn forged_authorization() -> AnonymousBallotAuthorizationV1 {
    let mut authorization = fixture_authorization(NAY_1);
    let mut proof = authorization.proof.into_bytes();
    proof[FORGED_PROOF_BYTE] ^= 0x01;
    authorization.proof = BallotProofBytesV1::new(proof).expect("exact length");
    authorization
}

/// The forged ballot with its pinned (valid) stamp: a well-stamped invalid proof.
pub fn forged_envelope() -> AnonymousBallotEnvelopeV1 {
    envelope_of(&forged_authorization(), FORGED_NONCE)
}

/// The canonical frame of `envelope`.
pub fn canonical_bytes(envelope: &AnonymousBallotEnvelopeV1) -> Vec<u8> {
    envelope.encode_canonical_bounded().expect("canonical")
}

#[cfg(test)]
mod tests {
    use iroha_data_model::governance::anonymous_ballot::digests::{
        stamp_payload_digest_v1, verify_stamp_v1,
    };

    use super::*;
    use crate::stamp::StampTargetV1;

    /// Every fixture authorization, the forged one last, with its pinned nonce.
    fn pinned() -> Vec<(String, AnonymousBallotAuthorizationV1, [u8; 32])> {
        let mut all: Vec<_> = (0..FIXTURE_BALLOTS.len())
            .map(|index| {
                (
                    format!("FIXTURE_BALLOTS[{index}]"),
                    fixture_authorization(index),
                    FIXTURE_BALLOTS[index].nonce,
                )
            })
            .collect();
        all.push((
            "FORGED_NONCE".to_owned(),
            forged_authorization(),
            FORGED_NONCE,
        ));
        all
    }

    #[test]
    fn the_pinned_stamps_reach_the_frozen_difficulty() {
        let context = scoped_context();
        assert_eq!(context.policy().binding.stamp_difficulty_bits, 28);
        for (name, authorization, nonce) in pinned() {
            assert!(
                verify_stamp_v1(
                    &authorization,
                    context.context(),
                    &AdmissionNonceV1::new(nonce)
                )
                .expect("stamp"),
                "{name}: the pinned nonce does not reach 28 bits; regenerate the fixture stamps"
            );
        }
    }

    #[test]
    fn the_fixture_roster_and_ballots_are_distinct() {
        let list = sealed_list();
        assert_eq!(list.seats, u16::from(SEATS));
        let nullifiers: Vec<_> = (0..FIXTURE_BALLOTS.len())
            .map(|index| fixture_authorization(index).nullifier)
            .collect();
        // Members 0..=3 have distinct nullifiers; NAY_0 shares member 0's.
        assert_eq!(nullifiers[NAY_0], nullifiers[AYE_0]);
        for (left, first) in nullifiers.iter().enumerate().take(4) {
            for second in &nullifiers[left + 1..4] {
                assert_ne!(first, second);
            }
        }
        assert_ne!(
            fixture_authorization(NAY_0).auth_v,
            fixture_authorization(AYE_0).auth_v
        );
    }

    /// Print every fixture's stamp payload digest, for mining with an external tool.
    #[test]
    #[ignore = "prints the fixture stamp payloads; run on demand"]
    fn print_fixture_stamp_payloads() {
        let context = scoped_context();
        for (name, authorization, _) in pinned() {
            let payload =
                stamp_payload_digest_v1(&authorization, context.context()).expect("payload");
            println!("{name} {}", payload.to_hex());
        }
    }

    /// Re-mine every pinned nonce with the crate's own parallel search and print the
    /// constants. Needs a release build to finish in reasonable time.
    #[test]
    #[ignore = "mines 28-bit stamps; run with --release after changing a fixture input"]
    fn regenerate_fixture_stamps() {
        let context = scoped_context();
        let threads = std::thread::available_parallelism().expect("parallelism");
        for (name, authorization, _) in pinned() {
            let target =
                StampTargetV1::for_ballot(&authorization, context.context()).expect("target");
            let mined = target
                .mine_parallel(
                    AdmissionNonceV1::new([0; 32]),
                    threads,
                    &std::sync::atomic::AtomicBool::new(false),
                )
                .expect("mined");
            println!("{name} = {:?}", mined.stamp.nonce.as_bytes());
        }
    }
}
