//! Anonymous on-chain ballot of the binding Parliament juries.
//!
//! The design is `specs/parliament_private_ballot_design.md` §3 and §8; the byte-level
//! construction is `specs/parliament_ballot_proof_profile.md` §6. Votes and counts are
//! public, a ballot carries no account identity, and its zero-knowledge proof shows that
//! the ballot statement is consistent with one sealed credential without revealing
//! which.
//!
//! This module holds the V1 wire types, their pinned canonical encodings, and the public
//! digests whose formulas need no proof-profile constant:
//!
//! - fixed-length values with raw codecs ([`Digest512`], [`CredentialCommitmentV1`],
//!   [`NullifierV1`], ...) and the exact-length proofs ([`BallotProofBytesV1`],
//!   [`RegistrationProofBytesV1`]);
//! - the ballot and its envelope ([`AnonymousBallotV1`], [`AnonymousBallotEnvelopeV1`],
//!   [`CanonicalAnonymousBallotEnvelopeV1`]), the stamp preimages and the compact corpus
//!   entry;
//! - the sealed list, registration mapping, roster preimage and authenticated context;
//! - the frozen ballot policy, the closure record with its checked outcome arithmetic,
//!   and the committed block-start outputs;
//! - the qualification record and the release-controlled gate constant.
//!
//! [`framing`] implements `Frame`, SHA3-512 and the pinned `Enc`; [`digests`] implements
//! the formulas of the integration decisions of 2026-10-18. The digests that bind the
//! construction domain `P16` (`B`, `R`, `scope`, `policy_hash`, `D_reg`, `D_v`) belong to
//! `iroha_parliament_ballot_proof`, which takes the `Enc` bytes produced here as its
//! opaque inputs.
//!
//! **Nothing here is qualified.** [`PARLIAMENT_BALLOT_QUALIFICATION_V1`] is `None`, so
//! binding production use stays disabled until the owner records qualification. Core
//! wiring (the transaction entrypoint, the rejection reason, block-start outputs, chain
//! parameters, state tables and the gate) is a separate integration phase.

mod ballot;
mod bytes;
mod closure;
mod context;
pub mod digests;
pub mod framing;
mod outcome;
mod output;
mod policy;
mod qualification;

pub use self::{
    ballot::{
        AdmissionStampV1, AnonymousBallotAuthorizationV1, AnonymousBallotCorpusEntryV1,
        AnonymousBallotEnvelopeV1, AnonymousBallotRejectionV1, AnonymousBallotV1, BallotChoiceV1,
        CanonicalAnonymousBallotEnvelopeV1,
    },
    bytes::{
        AdmissionNonceV1, BallotAuthorityBindingV1, BallotProofBytesV1, BallotScopeV1,
        CredentialCommitmentV1, Digest512, FixedBytesErrorV1, NullifierV1, ProofProfileIdV1,
        RegistrationAuthorizationV1, RegistrationProofBytesV1, VoteAuthorizationV1,
    },
    closure::{BallotClosureErrorV1, BallotClosureRecordV1},
    context::{
        AnonymousParliamentRosterRootPreimageV1, AnonymousRosterBindingV1,
        AuthenticatedBallotContextV1, BallotBodyContextV1, BallotContextErrorV1,
        CredentialRegistrationV1, SealedCredentialListBytesV1, SealedCredentialListV1,
        SealedRegistrationPairV1,
    },
    digests::AnonymousBallotCorpusErrorV1,
    framing::AnonymousBallotCodecErrorV1,
    outcome::{BallotDecisionV1, BallotOutcomeV1, BallotTallyErrorV1, ParliamentDecisionRuleV1},
    output::{
        CastingClockEstablishedV1, CastingOpenedV1, GovernanceBlockStartEventV1,
        GovernanceBlockStartOutputV1, SealedCredentialListPublishedV1,
    },
    policy::{
        BallotCapacityCommitmentV1, BodyDecisionModeV1, FrozenBallotPolicyErrorV1,
        FrozenBallotPolicyV1, FrozenLifecyclePolicyV1, FrozenSortitionPolicyV1,
        RequiredBodyPolicyV1,
    },
    qualification::{
        BallotQualificationRecordV1, BallotSecurityContractV1, BallotServiceContractV1,
        PARLIAMENT_BALLOT_QUALIFICATION_V1, QualifiedBallotParameterBoundsV1,
        parliament_ballot_qualified_v1,
    },
};
pub use crate::parameter::parliament_ballot::{
    BallotCastingCapacityV1, ParliamentBallotParameterErrorV1, ParliamentBallotParametersV1,
    parliament_ballot_capacity_v1,
};

/// Largest canonical anonymous-ballot envelope frame, `E_max` (integration decision 1).
pub const ANONYMOUS_BALLOT_ENVELOPE_MAX_BYTES_V1: usize = 262_144;

/// Largest canonical authenticated ballot context, `C_max`, which also bounds the
/// sealed-list object it contains (design §3.3, integration decision 5).
pub const BALLOT_CONTEXT_MAX_BYTES_V1: usize = 163_840;

/// Largest verifier input charged to one proof verification: `E_max + C_max`.
pub const BALLOT_VERIFIER_INPUT_MAX_BYTES_PER_CALL_V1: u64 = 425_984;

/// Fewest sealed seats of a binding body (design §3.3).
pub const MIN_SEALED_SEATS_V1: u16 = 3;

/// Most sealed seats of a binding body (design §3.3).
pub const MAX_SEALED_SEATS_V1: u16 = 1_000;

/// Fewest accepted ballots of a quorate binding ballot; also the turnout floor's lower
/// bound `max(3, Q)` (design §3.7).
pub const MIN_TURNOUT_V1: u16 = 3;

/// Registration-proof verification reservations per block, separate from the ballot
/// budget (integration decision 5; a protocol constant until it is committed policy).
pub const REGISTRATION_RESERVATIONS_PER_BLOCK_V1: u32 = 1;

/// Registration-proof verifier-input bytes per block, separate from the ballot budget.
pub const REGISTRATION_VERIFIER_INPUT_BYTES_PER_BLOCK_V1: u64 = 425_984;

/// Deterministic sample values shared by this module's tests.
#[cfg(test)]
pub(crate) mod test_fixtures {
    use iroha_crypto::{Hash, HashOf};

    use super::*;
    use crate::{
        NetworkId,
        account::AccountId,
        block::BlockHeader,
        governance::{
            GovernanceAnchorV1,
            types::{
                AbiVersion, AssignmentId, BodyElectionAttemptId, BodyInstanceId, ContractAbiHash,
                ContractCodeHash, DeployContractProposal, GovernanceAttemptId, ParliamentBody,
                ProposalContentId, ProposalKind, RiskTierV1,
            },
        },
    };

    /// A fixed Ed25519 account.
    pub fn account() -> AccountId {
        AccountId::new(
            "ed0120BDF918243253B1E731FA096194C8928DA37C4D3226F97EEBD18CF5523D758D6C"
                .parse()
                .expect("public key"),
        )
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

    pub fn network_id() -> NetworkId {
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::prehashed([0x5a; Hash::LENGTH]),
        ))
    }

    pub fn body_context() -> BallotBodyContextV1 {
        BallotBodyContextV1 {
            network_id: network_id(),
            governance_attempt_id: GovernanceAttemptId::new([0x11; 32]),
            election_attempt_id: BodyElectionAttemptId::new([0x22; 32]),
            body_role: ParliamentBody::PolicyJury,
        }
    }

    /// Commitment `tag` of a sorted list: the tag big-endian in its first two bytes.
    pub fn commitment(tag: u16) -> CredentialCommitmentV1 {
        let mut bytes = [0x77_u8; 128];
        bytes[..2].copy_from_slice(&tag.to_be_bytes());
        CredentialCommitmentV1::new(bytes)
    }

    pub fn commitments(count: u16) -> Vec<CredentialCommitmentV1> {
        (0..count).map(commitment).collect()
    }

    pub fn sealed_list(count: u16) -> SealedCredentialListV1 {
        SealedCredentialListV1::new(
            ProofProfileIdV1::V1,
            Digest512::new([0x33; 64]),
            commitments(count),
        )
        .expect("sorted fixture list")
    }

    pub fn assignment(tag: u8) -> AssignmentId {
        AssignmentId::new([tag; 32])
    }

    /// The Policy Jury snapshot of a standard-tier attempt with the SCCP-route pipeline
    /// and the default committed budgets at a 1,000 ms cadence.
    pub fn policy() -> FrozenBallotPolicyV1 {
        let required_bodies = [
            (ParliamentBody::RulesCommittee, 50),
            (ParliamentBody::AgendaCouncil, 150),
            (ParliamentBody::InterestPanel, 12),
            (ParliamentBody::ReviewPanel, 150),
            (ParliamentBody::CoordinationCouncil, 150),
            (ParliamentBody::FmaCommittee, 50),
            (ParliamentBody::OversightCommittee, 50),
            (ParliamentBody::PolicyJury, 500),
            (ParliamentBody::ConfirmationJury, 1_000),
        ]
        .into_iter()
        .map(|(body, target_seats)| RequiredBodyPolicyV1 {
            body,
            decision_mode: if matches!(
                body,
                ParliamentBody::PolicyJury | ParliamentBody::ConfirmationJury
            ) {
                BodyDecisionModeV1::AnonymousBallot
            } else {
                BodyDecisionModeV1::PublicFinding
            },
            target_seats,
            alternate_cap: 21,
        })
        .collect();
        let parameters = ParliamentBallotParametersV1::default();
        FrozenBallotPolicyV1 {
            governance_policy_version: 1,
            risk_tier: RiskTierV1::Standard,
            body_role: ParliamentBody::PolicyJury,
            required_bodies,
            profile_id: ProofProfileIdV1::V1,
            vote_notice_ms: parameters.vote_notice_ms,
            casting_window_ms: parameters.casting_window_ms,
            stamp_difficulty_bits: parameters.stamp_difficulty_bits,
            minimum_sealed_seats: 3,
            minimum_turnout: 3,
            quorum_numerator: 2,
            quorum_denominator: 3,
            decision_rule: ParliamentDecisionRuleV1::V1,
            maximum_seats: 1_000,
            sortition_policy: FrozenSortitionPolicyV1 {
                pulse_delay_blocks: 4,
                pulse_cadence_blocks: 3_600,
                cross_body_assignment_cap: 1,
                max_sortition_retries: 16,
                max_randomness_redraws: 16,
            },
            lifecycle_policy: FrozenLifecyclePolicyV1 {
                invitation_window_ms: 3_600_000,
                deliberation_window_ms: 3_600_000,
                enactment_delay_ms: 600_000,
            },
            capacity_commitment: BallotCapacityCommitmentV1::from_parameters(&parameters, 1_000),
        }
    }

    pub fn proof() -> BallotProofBytesV1 {
        BallotProofBytesV1::new(vec![0x6b; BallotProofBytesV1::LENGTH]).expect("exact length")
    }

    pub fn ballot(vote: BallotChoiceV1, nullifier: u8) -> AnonymousBallotV1 {
        AnonymousBallotV1 {
            scope: BallotScopeV1::new([0x44; 64]),
            vote,
            nullifier: NullifierV1::new([nullifier; 128]),
            auth_v: VoteAuthorizationV1::new([0x55; 64]),
            profile_id: ProofProfileIdV1::V1,
            stamp: AdmissionStampV1 {
                nonce: AdmissionNonceV1::new([0x66; 32]),
            },
            proof: proof(),
        }
    }

    pub fn envelope(vote: BallotChoiceV1, nullifier: u8) -> AnonymousBallotEnvelopeV1 {
        AnonymousBallotEnvelopeV1 {
            network_id: network_id(),
            ballot: ballot(vote, nullifier),
        }
    }

    pub fn context() -> AuthenticatedBallotContextV1 {
        let list = sealed_list(5);
        AuthenticatedBallotContextV1 {
            body_context: body_context(),
            proposal_digest: Digest512::new([0x88; 64]),
            body_context_digest: list.body_context_digest,
            list_digest: Digest512::new([0x99; 64]),
            seats: list.seats,
            commitments: list.commitments,
            profile_id: ProofProfileIdV1::V1,
            policy: policy(),
            policy_hash: Digest512::new([0xaa; 64]),
        }
    }

    pub const fn anchor(height: u64, position: u32, timestamp_ms: u64) -> GovernanceAnchorV1 {
        GovernanceAnchorV1 {
            height,
            position,
            timestamp_ms,
        }
    }

    /// A valid closure record for `seats` with the given counts; the outcome and the
    /// narrow flag are recomputed under the standard tier.
    pub fn closure(seats: u16, aye: u32, nay: u32, abstain: u32) -> BallotClosureRecordV1 {
        let decision = ParliamentDecisionRuleV1::StrictAyeMajority
            .decide(
                ParliamentBody::PolicyJury,
                RiskTierV1::Standard,
                seats,
                aye,
                nay,
                abstain,
            )
            .expect("valid counts");
        BallotClosureRecordV1 {
            network_id: network_id(),
            proposal_content_id: ProposalContentId::new([0x01; 32]),
            proposal_digest: Digest512::new([0x02; 64]),
            governance_attempt_id: GovernanceAttemptId::new([0x11; 32]),
            election_attempt_id: BodyElectionAttemptId::new([0x22; 32]),
            body_instance_id: BodyInstanceId::new([0x03; 32]),
            body_role: ParliamentBody::PolicyJury,
            scope: BallotScopeV1::new([0x44; 64]),
            seats,
            profile_id: ProofProfileIdV1::V1,
            policy_hash: Digest512::new([0xaa; 64]),
            list_digest: Digest512::new([0x99; 64]),
            registration_mapping_digest: Digest512::new([0x04; 64]),
            opening_anchor: anchor(100, 2, 1_000_000),
            casting_clock_height: 101,
            casting_clock_timestamp_ms: 1_001_000,
            casting_window_ms: 86_400_000,
            closing_ms: 87_401_000,
            closure_anchor: anchor(90_000, 0, 87_401_500),
            corpus_root: Digest512::new([0x05; 64]),
            accepted_ballots: aye + nay + abstain,
            aye,
            nay,
            abstain,
            outcome: decision.outcome,
            narrow: decision.narrow,
        }
    }
}

#[cfg(test)]
mod proof_crate_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::types::{
        MAX_PARLIAMENT_BODY_TARGET_SEATS_V1, MIN_PARLIAMENT_HIDDEN_BALLOT_ANONYMITY_V1,
    };

    #[test]
    fn the_resource_constants_are_the_integration_decisions() {
        assert_eq!(ANONYMOUS_BALLOT_ENVELOPE_MAX_BYTES_V1, 262_144);
        assert_eq!(BALLOT_CONTEXT_MAX_BYTES_V1, 163_840);
        assert_eq!(
            BALLOT_VERIFIER_INPUT_MAX_BYTES_PER_CALL_V1,
            u64::try_from(ANONYMOUS_BALLOT_ENVELOPE_MAX_BYTES_V1 + BALLOT_CONTEXT_MAX_BYTES_V1)
                .expect("small")
        );
        assert_eq!(
            REGISTRATION_VERIFIER_INPUT_BYTES_PER_BLOCK_V1,
            BALLOT_VERIFIER_INPUT_MAX_BYTES_PER_CALL_V1
        );
        assert_eq!(REGISTRATION_RESERVATIONS_PER_BLOCK_V1, 1);
        assert_eq!(
            u32::from(MAX_SEALED_SEATS_V1),
            MAX_PARLIAMENT_BODY_TARGET_SEATS_V1
        );
        assert_eq!(
            u32::from(MIN_SEALED_SEATS_V1),
            MIN_PARLIAMENT_HIDDEN_BALLOT_ANONYMITY_V1
        );
        assert_eq!(MIN_TURNOUT_V1, MIN_SEALED_SEATS_V1);
    }
}
